/**
 * Cas
 */
import _ from "underscore";
import url from "url";
import http from "http";
import https from "https";
import uuid from "uuid";
import { Strategy as BaseStrategy } from "passport-strategy";
import util from "util";
import { parseString, processors } from "xml2js";

type VersionOptions = "CAS1.0" | "CAS2.0" | "CAS3.0";
type VerifyFunction = any;

class Strategy2 extends BaseStrategy {
  name = "cas";

  private version: VersionOptions;
  private ssoBase: string;
  private serverBaseURL?: string;
  private validateURI: string;
  private serviceURL?: string;
  private useSaml: boolean;
  private passReqToCallback: boolean;
  private verify: VerifyFunction;

  private parsed: url.UrlWithStringQuery;
  private client: typeof http | typeof https;

  constructor(
    options: {
      version?: VersionOptions;
      ssoBaseURL: string;
      serverBaseURL?: string;
      validateURL?: string;
      serviceURL?: string;
      useSaml?: boolean;
      passReqToCallback?: boolean;
    },
    verify: VerifyFunction
  ) {
    super();

    this.version = options.version ?? "CAS1.0";
    this.ssoBase = options.ssoBaseURL;
    this.serverBaseURL = options.serverBaseURL;
    this.serviceURL = options.serviceURL;
    this.useSaml = options.useSaml ?? false;
    this.passReqToCallback = options.passReqToCallback ?? false;

    this.parsed = url.parse(this.ssoBase);
    if (this.parsed.protocol === "http:") {
      this.client = http;
    } else {
      this.client = https;
    }

    if (!verify) {
      throw new Error("cas authentication strategy requires a verify function");
    }
    this.verify = verify;

    let validateUri: string;
    switch (this.version) {
      case "CAS1.0":
        validateUri = "/validate";
        break;
      case "CAS2.0":
        validateUri = "/serviceValidate";
      case "CAS3.0":
        if (this.useSaml) {
          validateUri = "/samlValidate";
        } else {
          validateUri = "/p3/serviceValidate";
        }
        break;
      default:
        throw new Error("unsupported version " + this.version);
    }
    this.validateURI = options.validateURL ?? validateUri;
  }
}

function Strategy(options, verify) {
  var xmlParseOpts = {
    trim: true,
    normalize: true,
    explicitArray: false,
    tagNameProcessors: [processors.normalize, processors.stripPrefix],
  };

  var self = this;
  switch (this.version) {
    case "CAS1.0":
      this._validateUri = "/validate";
      this._validate = function (req, body, verified) {
        var lines = body.split("\n");
        if (lines.length >= 1) {
          if (lines[0] === "no") {
            return verified(new Error("Authentication failed"));
          } else if (lines[0] === "yes" && lines.length >= 2) {
            if (self._passReqToCallback) {
              self._verify(req, lines[1], verified);
            } else {
              self._verify(lines[1], verified);
            }
            return;
          }
        }
        return verified(new Error("The response from the server was bad"));
      };
      break;
    case "CAS3.0":
      if (this.useSaml) {
        this._validateUri = "/samlValidate";
        this._validate = function (req, body, verified) {
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
                var attributes = {};
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
                if (self._passReqToCallback) {
                  self._verify(req, profile, verified);
                } else {
                  self._verify(profile, verified);
                }
                return;
              }
              return verified(new Error("Authentication failed"));
            } catch (e) {
              return verified(new Error("Authentication failed"));
            }
          });
        };
      } else {
        this._validateUri = "/p3/serviceValidate";
        this._validate = function (req, body, verified) {
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
                if (self._passReqToCallback) {
                  self._verify(req, success, verified);
                } else {
                  self._verify(success, verified);
                }
                return;
              }
              return verified(new Error("Authentication failed"));
            } catch (e) {
              return verified(new Error("Authentication failed"));
            }
          });
        };
      }
      break;
    default:
      throw new Error("unsupported version " + this.version);
  }
}

Strategy.prototype.service = function (req) {
  var serviceURL = this.serviceURL || req.originalUrl;
  var resolvedURL = url.resolve(this.serverBaseURL, serviceURL);
  var parsedURL = url.parse(resolvedURL, true);
  delete parsedURL.query.ticket;
  delete parsedURL.search;
  return url.format(parsedURL);
};

Strategy.prototype.authenticate = function (req, options) {
  options = options || {};

  // CAS Logout flow as described in
  // https://wiki.jasig.org/display/CAS/Proposal%3A+Front-Channel+Single+Sign-Out var relayState = req.query.RelayState;
  var relayState = req.query.RelayState;
  if (relayState) {
    // logout locally
    req.logout();
    return this.redirect(
      this.ssoBase + "/logout?_eventId=next&RelayState=" + relayState
    );
  }

  var service = this.service(req);

  var ticket = req.query["ticket"];
  if (!ticket) {
    var redirectURL = url.parse(this.ssoBase + "/login", true);

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

  var self = this;
  var verified = function (err, user, info) {
    if (err) {
      return self.error(err);
    }
    if (!user) {
      return self.fail(info);
    }
    self.success(user, info);
  };
  var _validateUri = this.validateURL || this._validateUri;

  var _handleResponse = function (response) {
    response.setEncoding("utf8");
    var body = "";
    response.on("data", function (chunk) {
      return (body += chunk);
    });
    return response.on("end", function () {
      return self._validate(req, body, verified);
    });
  };

  if (this.useSaml) {
    var requestId = uuid.v4();
    var issueInstant = new Date().toISOString();
    var soapEnvelope = util.format(
      '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1" MinorVersion="1" RequestID="%s" IssueInstant="%s"><samlp:AssertionArtifact>%s</samlp:AssertionArtifact></samlp:Request></SOAP-ENV:Body></SOAP-ENV:Envelope>',
      requestId,
      issueInstant,
      ticket
    );
    var request = this.client.request(
      {
        host: this.parsed.hostname,
        port: this.parsed.port,
        method: "POST",
        path: url.format({
          pathname: this.parsed.pathname + _validateUri,
          query: {
            TARGET: service,
          },
        }),
        headers: {
          "Content-Type": "text/xml",
        },
      },
      _handleResponse
    );

    request.on("error", function (e) {
      return self.fail(new Error(e));
    });
    request.write(soapEnvelope);
    request.end();
  } else {
    var get = this.client.get(
      {
        host: this.parsed.hostname,
        port: this.parsed.port,
        path: url.format({
          pathname: this.parsed.pathname + _validateUri,
          query: {
            ticket: ticket,
            service: service,
          },
        }),
        headers: {
          "Content-Type": "text/xml",
        },
      },
      _handleResponse
    );

    get.on("error", function (e) {
      return self.fail(new Error(e));
    });
  }
};

exports.Strategy = Strategy;
