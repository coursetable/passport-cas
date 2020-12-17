/**
 * Cas
 */
import _ from "underscore";
import url from "url";
import axios from "axios";
import uuid from "uuid";
import { Strategy as BaseStrategy } from "passport-strategy";
import util from "util";
import { parseString, processors } from "xml2js";
import express from "express";

type CasInfo =
  | string
  | {
      user: any;
      attributes: any;
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
      return lines[1];
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
      const profile = {
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

  authenticate(req: express.Request, options?: any): void {
    options = options || {};

    const service = this.service(req);
    const ticket = req.query["ticket"];
    if (!ticket) {
      const redirectURL = url.parse(this.ssoBase + "/login", true);

      redirectURL.query.service = service;
      // copy loginParams in login query
      for (var property in options.loginParams) {
        var loginParam = options.loginParams[property];
        if (loginParam) {
          redirectURL.query[property] = loginParam;
        }
      }
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
        console.log(response);
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
            return this.error(err);
          }
          if (!user) {
            return this.fail(info);
          }
          this.success(user, info);
        });
      })
      .catch((error) => {
        console.log("handling some error");
        return this.error(error);
      });
  }

  /**
   * Generate the "service" parameter for the CAS callback URL.
   */
  private service(req: express.Request): string {
    const defaultServerBaseUrl = `${req.protocol}://${req.hostname}`;
    var serviceURL = this.callbackURL || req.originalUrl;
    var resolvedURL = url.resolve(
      this.serverBaseURL ?? defaultServerBaseUrl,
      serviceURL
    );
    var parsedURL = url.parse(resolvedURL, true);
    delete parsedURL.query.ticket;
    parsedURL.search = null;
    return url.format(parsedURL);
  }
}

export default Strategy;
