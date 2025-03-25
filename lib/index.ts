import url from "url";
import { v4 as uuidV4 } from "uuid";
import { Strategy as BaseStrategy } from "passport-strategy";
import { parseString, processors } from "xml2js";
import type express from "express";

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
};
const validateResponseCas3saml = async (body: string): Promise<CasInfo> => {
  const result = await parseXmlString(body);
  const response = result.envelope.body.response;
  const success = response.status.statuscode["$"].Value.match(/Success$/);
  if (success) {
    const attributes: NonNullable<CasInfo["attributes"]> = {};
    Object.values(response.assertion.attributestatement.attribute).forEach(
      (attribute: any) => {
        attributes[attribute["$"].AttributeName.toLowerCase()] =
          attribute.attributevalue;
      }
    );
    const profile: CasInfo = {
      user: response.assertion.authenticationstatement.subject.nameidentifier,
      attributes,
    };
    return profile;
  }
  throw new Error("Authentication failed");
};

export class Strategy extends BaseStrategy {
  name = "cas";

  private version: VersionOptions;
  private ssoBaseURL: string;
  private serverBaseURL?: string;
  private validateURL: string;
  private callbackURL?: string;
  private verify: VerifyFunction;

  constructor(
    options: {
      version: VersionOptions;
      ssoBaseURL: string;
      serverBaseURL?: string;
      validateURL?: string;
      callbackURL?: string;
    },
    verify: VerifyFunction
  ) {
    super();
    if (!options.version) {
      throw new Error("CAS version is required");
    }
    if (!options.ssoBaseURL) {
      throw new Error("CAS ssoBaseURL is required");
    }
    if (!verify) {
      throw new Error("CAS authentication strategy requires a verify function");
    }

    this.version = options.version;
    this.ssoBaseURL = options.ssoBaseURL;
    this.serverBaseURL = options.serverBaseURL;
    this.callbackURL = options.callbackURL;
    this.verify = verify;

    this.validateURL =
      options.validateURL ??
      (() => {
        switch (this.version) {
          case "CAS1.0":
            return "/validate";
          case "CAS2.0":
            return "/serviceValidate";
          case "CAS3.0":
            return "/p3/serviceValidate";
          case "CAS2.0-with-saml":
          case "CAS3.0-with-saml":
            return "/samlValidate";
          default:
            const _exhaustiveCheck: never = this.version;
            throw new Error("Unsupported version " + this.version);
        }
      })();
  }

  override authenticate(
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
      const redirectURL = url.parse(this.ssoBaseURL + "/login", true);

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

    let fetchValidation: Promise<Response>;
    if (
      this.version === "CAS3.0-with-saml" ||
      this.version === "CAS2.0-with-saml"
    ) {
      const requestId = uuidV4();
      const issueInstant = new Date().toISOString();
      const soapEnvelope = `<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1" MinorVersion="1" RequestID="${requestId}" IssueInstant="${issueInstant}"><samlp:AssertionArtifact>${ticket}</samlp:AssertionArtifact></samlp:Request></SOAP-ENV:Body></SOAP-ENV:Envelope>`;

      fetchValidation = fetch(
        `${this.ssoBaseURL}${this.validateURL}?TARGET=${service}`,
        {
          method: "POST",
          body: soapEnvelope,
          headers: {
            "Content-Type": "text/xml",
          },
        }
      );
    } else {
      fetchValidation = fetch(
        `${this.ssoBaseURL}${this.validateURL}?ticket=${ticket}&service=${service}`,
        {
          method: "GET",
          headers: {
            "Content-Type": "text/xml",
          },
        }
      );
    }

    fetchValidation
      .then((response) => response.text())
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
            throw new Error("Unsupported version " + this.version);
        }
      })
      .then((user) =>
        this.verify(user, (err: any, user?: any, info?: any): void => {
          // Finish authentication flow.
          if (err) {
            return this.error(
              new Error("user-provided verify function failed", { cause: err })
            );
          }
          if (!user) {
            return this.fail(info);
          }
          this.success(user, info);
        })
      )
      .catch((err) =>
        this.error(new Error("Error in validation", { cause: err }))
      );
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
      if (Array.isArray(forwardHeader)) {
        forwardHeader = forwardHeader[0];
      }
      const host = forwardHeader.split(",")[0];

      // Then, determine proto used. We default to http here.
      let forwardProto = req.headers["x-forwarded-proto"];
      if (Array.isArray(forwardProto)) {
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
