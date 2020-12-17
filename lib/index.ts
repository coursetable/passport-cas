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

class Strategy extends BaseStrategy {
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

    const self = this;

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

      axios
        .post(`${this.ssoBase}/${this.validateURI}`, soapEnvelope, {
          params: {
            TARGET: service,
          },
          headers: {
            "Content-Type": "text/xml",
          },
        })
        .then((response) => {
          return this.validate(req, response.data);
        })
        .catch((error) => {
          return this.error(error);
        });
    } else {
      axios
        .get(`${this.ssoBase}/${this.validateURI}`, {
          params: {
            ticket: ticket,
            service: service,
          },
          headers: {
            "Content-Type": "text/xml",
          },
        })
        .then((response) => {
          return self.validate(req, response.data);
        })
        .catch((error) => {
          return self.error(error);
        });
    }
  }

  /**
   * Finish authentication flow.
   */
  private finish(err: any, user?: any, info?: any): void {
    if (err) {
      return this.error(err);
    }
    if (!user) {
      return this.fail(info);
    }
    this.success(user, info);
  }

  /**
   * Validates a response from the server.
   */
  private validate(req: express.Request, body: string): void {
    const self = this;
    const verified = this.finish;

    const xmlParseOpts = {
      trim: true,
      normalize: true,
      explicitArray: false,
      tagNameProcessors: [processors.normalize, processors.stripPrefix],
    };

    switch (this.version) {
      case "CAS1.0":
        {
          var lines = body.split("\n");
          if (lines.length >= 1) {
            if (lines[0] === "no") {
              return verified(new Error("Authentication failed"));
            } else if (lines[0] === "yes" && lines.length >= 2) {
              return self._verify(lines[1], verified);
            }
          }
          return verified(new Error("The response from the server was bad"));
        }
        break;
      case "CAS2.0":
      case "CAS3.0":
        {
          parseString(body, xmlParseOpts, function (err, result) {
            if (err) {
              return verified(
                new Error("The response from the server was bad")
              );
            }
            try {
              if (result.serviceresponse.authenticationfailure) {
                return verified(
                  new Error(
                    "Authentication failed " +
                      result.serviceresponse.authenticationfailure.$.code
                  )
                );
              }
              var success = result.serviceresponse.authenticationsuccess;
              if (success) {
                return self._verify(success, verified);
              }
              return verified(new Error("Authentication failed"));
            } catch (e) {
              return verified(new Error("Authentication failed"));
            }
          });
        }
        break;
      case "CAS2.0-with-saml":
      case "CAS3.0-with-saml":
        {
          parseString(body, xmlParseOpts, function (err, result) {
            if (err) {
              return verified(
                new Error("The response from the server was bad")
              );
            }
            try {
              var response = result.envelope.body.response;
              var success = response.status.statuscode["$"].Value.match(
                /Success$/
              );
              if (success) {
                var attributes: any = {};
                _.each(
                  response.assertion.attributestatement.attribute,
                  function (attribute) {
                    attributes[attribute["$"].AttributeName.toLowerCase()] =
                      attribute.attributevalue;
                  }
                );
                var profile = {
                  user:
                    response.assertion.authenticationstatement.subject
                      .nameidentifier,
                  attributes: attributes,
                };
                return self._verify(profile, verified);
              }
              return verified(new Error("Authentication failed"));
            } catch (e) {
              return verified(new Error("Authentication failed"));
            }
          });
        }
        break;
      default:
        const _exhaustiveCheck: never = this.version;
        throw new Error("unsupported version " + this.version);
    }
  }

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

exports.Strategy = Strategy;
