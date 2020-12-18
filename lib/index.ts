/**
 * Cas
 */
import _, { isArray } from "underscore";
import url from "url";
import axios from "axios";
import uuid from "uuid";
import { Strategy as BaseStrategy } from "passport-strategy";
import util from "util";
import { parseString, processors } from "xml2js";
import express from "express";
import VError from "verror";

type CasInfo = {
  user: string;
  attributes?: {
    [key in string]: string | string[];
  };
};
type VersionOptions =
  | "CAS1.0"
  | "CAS2.0"
  | "CAS2.0-with-saml"
  | "CAS3.0"
  | "CAS3.0-with-saml";
type VerifyDoneCallback = (err: any, user?: any, info?: any) => void;
type VerifyFunction = (login: CasInfo, done: VerifyDoneCallback) => void;

const parseXmlString = (xml: string): Promise<any> => {
  const xmlParseOpts = {
    trim: true,
    normalize: true,
    explicitArray: false,
    tagNameProcessors: [processors.normalize, processors.stripPrefix],
  };
  return new Promise<any>((resolve, reject) => {
    parseString(xml, xmlParseOpts, (err, result) => {
      if (err) {
        return reject(err);
      }
      resolve(result);
    });
  });
};

const validateResponseCas1 = async (body: string): Promise<CasInfo> => {
  const lines = body.split("\n");
  if (lines.length >= 1) {
    if (lines[0] === "no") {
      throw new Error("Authentication rejected");
    } else if (lines[0] === "yes" && lines.length >= 2) {
      const profile: CasInfo = {
        user: lines[1],
      };
      return profile;
    }
  }
  throw new Error("The response from the server was bad");
};
const validateResponseCas3 = async (body: string): Promise<CasInfo> => {
  const result = await parseXmlString(body);

  try {
    if (result.serviceresponse.authenticationfailure) {
      throw new Error(
        "Authentication failed " +
          result.serviceresponse.authenticationfailure.$.code
      );
    }
    const success = result.serviceresponse.authenticationsuccess;
    if (success) {
      return success;
    }
    throw new Error("Authentication failed but success present");
  } catch (e) {
    throw new Error("Authentication failed - XML parsing issue");
  }
};
const validateResponseCas3saml = async (body: string): Promise<CasInfo> => {
  const result = await parseXmlString(body);

  try {
    var response = result.envelope.body.response;
    var success = response.status.statuscode["$"].Value.match(/Success$/);
    if (success) {
      let attributes: any = {};
      _.each(
        response.assertion.attributestatement.attribute,
        function (attribute) {
          attributes[attribute["$"].AttributeName.toLowerCase()] =
            attribute.attributevalue;
        }
      );
      const profile: CasInfo = {
        user: response.assertion.authenticationstatement.subject.nameidentifier,
        attributes: attributes,
      };
      return profile;
    }
    throw new Error("Authentication failed");
  } catch (e) {
    throw new Error("Authentication failed");
  }
};

export class Strategy extends BaseStrategy {
  name = "cas";

  private version: VersionOptions;
  private ssoBase: string;
  private serverBaseURL?: string;
  private validateURI: string;
  private callbackURL?: string;
  private _verify: VerifyFunction;

  constructor(
    options: {
      version?: VersionOptions;
      ssoBaseURL: string;
      serverBaseURL?: string;
      validateURL?: string;
      callbackURL?: string;
      useSaml?: boolean;
      passReqToCallback?: boolean;
    },
    verify: VerifyFunction
  ) {
    super();

    this.version = options.version ?? "CAS1.0";
    this.ssoBase = options.ssoBaseURL;
    this.serverBaseURL = options.serverBaseURL;
    this.callbackURL = options.callbackURL;

    if (!verify) {
      throw new Error("cas authentication strategy requires a verify function");
    }
    this._verify = verify;

    let validateUri: string;
    switch (this.version) {
      case "CAS1.0":
        validateUri = "/validate";
        break;
      case "CAS2.0":
        validateUri = "/serviceValidate";
      case "CAS3.0":
        validateUri = "/p3/serviceValidate";
        break;
      case "CAS2.0-with-saml":
      case "CAS3.0-with-saml":
        validateUri = "/samlValidate";
        break;
      default:
        const _exhaustiveCheck: never = this.version;
        throw new Error("unsupported version " + this.version);
    }
    this.validateURI = options.validateURL ?? validateUri;
  }

  authenticate(
    req: express.Request,
    options?: {
      /** Preserve the original query parameters. Default true. */
      copyQueryParameters?: boolean;
    }
  ): void {
    options = options ?? {};

    const service = this.service(req);
    const ticket = req.query["ticket"];
    if (!ticket) {
      const redirectURL = url.parse(this.ssoBase + "/login", true);

      if (options.copyQueryParameters ?? true) {
        // Copy query parameters from original request.
        const originalQuery = url.parse(req.url, true).query;
        if (originalQuery) {
          redirectURL.query = originalQuery;
        }
      }

      redirectURL.query.service = service;
      return this.redirect(url.format(redirectURL));
    }

    let fetchValidation;
    if (
      this.version === "CAS3.0-with-saml" ||
      this.version === "CAS2.0-with-saml"
    ) {
      const requestId = uuid.v4();
      const issueInstant = new Date().toISOString();
      const soapEnvelope = util.format(
        '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1" MinorVersion="1" RequestID="%s" IssueInstant="%s"><samlp:AssertionArtifact>%s</samlp:AssertionArtifact></samlp:Request></SOAP-ENV:Body></SOAP-ENV:Envelope>',
        requestId,
        issueInstant,
        ticket
      );

      fetchValidation = axios.post(
        `${this.ssoBase}${this.validateURI}`,
        soapEnvelope,
        {
          params: {
            TARGET: service,
          },
          headers: {
            "Content-Type": "text/xml",
          },
        }
      );
    } else {
      fetchValidation = axios.get(`${this.ssoBase}${this.validateURI}`, {
        params: {
          ticket: ticket,
          service: service,
        },
        headers: {
          "Content-Type": "text/xml",
        },
      });
    }

    fetchValidation
      .then((response) => {
        return response.data as string;
      })
      .then((xml) => {
        switch (this.version) {
          case "CAS1.0":
            return validateResponseCas1(xml);
          case "CAS2.0":
          case "CAS3.0":
            return validateResponseCas3(xml);
          case "CAS2.0-with-saml":
          case "CAS3.0-with-saml":
            return validateResponseCas3saml(xml);
          default:
            const _exhaustiveCheck: never = this.version;
            throw new Error("unsupported version " + this.version);
        }
      })
      .then((user) => {
        // Call user-provided verify function.
        return this._verify(user, (err: any, user?: any, info?: any): void => {
          // Finish authentication flow.
          if (err) {
            return this.error(
              new VError(err, "user-provided verify function failed")
            );
          }
          if (!user) {
            return this.fail(info);
          }
          this.success(user, info);
        });
      })
      .catch((err) => {
        const error = new VError(err, "Error in validation");
        return this.error(error);
      });
  }

  /**
   * Generate the "service" parameter for the CAS callback URL.
   */
  private service(req: express.Request): string {
    let baseUrl;
    if (this.serverBaseURL) {
      baseUrl = this.serverBaseURL;
    } else if (req.headers["x-forwarded-host"]) {
      // We need to include this in Express <= v4, since the behavior
      // is to strip the port number by default. This is fixed in Express v5.

      // First, determine host + port.
      let forwardHeader = req.headers["x-forwarded-host"];
      if (isArray(forwardHeader)) {
        forwardHeader = forwardHeader[0];
      }
      const host = forwardHeader.split(",")[0];

      // Then, determine proto used. We default to http here.
      let forwardProto = req.headers["x-forwarded-proto"];
      if (isArray(forwardProto)) {
        forwardProto = forwardProto[0];
      }
      const proto = forwardProto ? forwardProto.split(",")[0] : "http";

      baseUrl = `${proto}://${host}`;
    } else if (req.headers["host"]) {
      // Fallback to "HOST" header.
      baseUrl = `${req.protocol}://${req.headers["host"]}`;
    } else {
      // Final fallback is to req.hostname, generated by Express. As mentioned
      // above, this won't have a port number and so we attempt to use it last.
      baseUrl = `${req.protocol}://${req.hostname}`;
    }

    const serviceURL = this.callbackURL || req.originalUrl;
    const resolvedURL = url.resolve(baseUrl, serviceURL);
    const parsedURL = url.parse(resolvedURL, true);
    delete parsedURL.query.ticket;
    parsedURL.search = null;
    return url.format(parsedURL);
  }
}

export default Strategy;
