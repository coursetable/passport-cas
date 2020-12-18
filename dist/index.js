"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Strategy = void 0;
/**
 * Cas
 */
var underscore_1 = __importStar(require("underscore"));
var url_1 = __importDefault(require("url"));
var axios_1 = __importDefault(require("axios"));
var uuid_1 = __importDefault(require("uuid"));
var passport_strategy_1 = require("passport-strategy");
var util_1 = __importDefault(require("util"));
var xml2js_1 = require("xml2js");
var verror_1 = __importDefault(require("verror"));
var parseXmlString = function (xml) {
    var xmlParseOpts = {
        trim: true,
        normalize: true,
        explicitArray: false,
        tagNameProcessors: [xml2js_1.processors.normalize, xml2js_1.processors.stripPrefix],
    };
    return new Promise(function (resolve, reject) {
        xml2js_1.parseString(xml, xmlParseOpts, function (err, result) {
            if (err) {
                return reject(err);
            }
            resolve(result);
        });
    });
};
var validateResponseCas1 = function (body) { return __awaiter(void 0, void 0, void 0, function () {
    var lines, profile;
    return __generator(this, function (_a) {
        lines = body.split("\n");
        if (lines.length >= 1) {
            if (lines[0] === "no") {
                throw new Error("Authentication rejected");
            }
            else if (lines[0] === "yes" && lines.length >= 2) {
                profile = {
                    user: lines[1],
                };
                return [2 /*return*/, profile];
            }
        }
        throw new Error("The response from the server was bad");
    });
}); };
var validateResponseCas3 = function (body) { return __awaiter(void 0, void 0, void 0, function () {
    var result, success;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0: return [4 /*yield*/, parseXmlString(body)];
            case 1:
                result = _a.sent();
                try {
                    if (result.serviceresponse.authenticationfailure) {
                        throw new Error("Authentication failed " +
                            result.serviceresponse.authenticationfailure.$.code);
                    }
                    success = result.serviceresponse.authenticationsuccess;
                    if (success) {
                        return [2 /*return*/, success];
                    }
                    throw new Error("Authentication failed but success present");
                }
                catch (e) {
                    throw new Error("Authentication failed - XML parsing issue");
                }
                return [2 /*return*/];
        }
    });
}); };
var validateResponseCas3saml = function (body) { return __awaiter(void 0, void 0, void 0, function () {
    var result, response, success, attributes_1, profile;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0: return [4 /*yield*/, parseXmlString(body)];
            case 1:
                result = _a.sent();
                try {
                    response = result.envelope.body.response;
                    success = response.status.statuscode["$"].Value.match(/Success$/);
                    if (success) {
                        attributes_1 = {};
                        underscore_1.default.each(response.assertion.attributestatement.attribute, function (attribute) {
                            attributes_1[attribute["$"].AttributeName.toLowerCase()] =
                                attribute.attributevalue;
                        });
                        profile = {
                            user: response.assertion.authenticationstatement.subject.nameidentifier,
                            attributes: attributes_1,
                        };
                        return [2 /*return*/, profile];
                    }
                    throw new Error("Authentication failed");
                }
                catch (e) {
                    throw new Error("Authentication failed");
                }
                return [2 /*return*/];
        }
    });
}); };
var Strategy = /** @class */ (function (_super) {
    __extends(Strategy, _super);
    function Strategy(options, verify) {
        var _a, _b;
        var _this = _super.call(this) || this;
        _this.name = "cas";
        _this.version = (_a = options.version) !== null && _a !== void 0 ? _a : "CAS1.0";
        _this.ssoBase = options.ssoBaseURL;
        _this.serverBaseURL = options.serverBaseURL;
        _this.callbackURL = options.callbackURL;
        if (!verify) {
            throw new Error("cas authentication strategy requires a verify function");
        }
        _this._verify = verify;
        var validateUri;
        switch (_this.version) {
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
                var _exhaustiveCheck = _this.version;
                throw new Error("unsupported version " + _this.version);
        }
        _this.validateURI = (_b = options.validateURL) !== null && _b !== void 0 ? _b : validateUri;
        return _this;
    }
    Strategy.prototype.authenticate = function (req, options) {
        var _this = this;
        var _a;
        options = options !== null && options !== void 0 ? options : {};
        var service = this.service(req);
        var ticket = req.query["ticket"];
        if (!ticket) {
            var redirectURL = url_1.default.parse(this.ssoBase + "/login", true);
            if ((_a = options.copyQueryParameters) !== null && _a !== void 0 ? _a : true) {
                // Copy query parameters from original request.
                var originalQuery = url_1.default.parse(req.url, true).query;
                if (originalQuery) {
                    redirectURL.query = originalQuery;
                }
            }
            redirectURL.query.service = service;
            return this.redirect(url_1.default.format(redirectURL));
        }
        var fetchValidation;
        if (this.version === "CAS3.0-with-saml" ||
            this.version === "CAS2.0-with-saml") {
            var requestId = uuid_1.default.v4();
            var issueInstant = new Date().toISOString();
            var soapEnvelope = util_1.default.format('<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1" MinorVersion="1" RequestID="%s" IssueInstant="%s"><samlp:AssertionArtifact>%s</samlp:AssertionArtifact></samlp:Request></SOAP-ENV:Body></SOAP-ENV:Envelope>', requestId, issueInstant, ticket);
            fetchValidation = axios_1.default.post("" + this.ssoBase + this.validateURI, soapEnvelope, {
                params: {
                    TARGET: service,
                },
                headers: {
                    "Content-Type": "text/xml",
                },
            });
        }
        else {
            fetchValidation = axios_1.default.get("" + this.ssoBase + this.validateURI, {
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
            .then(function (response) {
            return response.data;
        })
            .then(function (xml) {
            switch (_this.version) {
                case "CAS1.0":
                    return validateResponseCas1(xml);
                case "CAS2.0":
                case "CAS3.0":
                    return validateResponseCas3(xml);
                case "CAS2.0-with-saml":
                case "CAS3.0-with-saml":
                    return validateResponseCas3saml(xml);
                default:
                    var _exhaustiveCheck = _this.version;
                    throw new Error("unsupported version " + _this.version);
            }
        })
            .then(function (user) {
            // Call user-provided verify function.
            return _this._verify(user, function (err, user, info) {
                // Finish authentication flow.
                if (err) {
                    return _this.error(new verror_1.default(err, "user-provided verify function failed"));
                }
                if (!user) {
                    return _this.fail(info);
                }
                _this.success(user, info);
            });
        })
            .catch(function (err) {
            var error = new verror_1.default(err, "Error in validation");
            return _this.error(error);
        });
    };
    /**
     * Generate the "service" parameter for the CAS callback URL.
     */
    Strategy.prototype.service = function (req) {
        var baseUrl;
        if (this.serverBaseURL) {
            baseUrl = this.serverBaseURL;
        }
        else if (req.headers["x-forwarded-host"]) {
            // We need to include this in Express <= v4, since the behavior
            // is to strip the port number by default. This is fixed in Express v5.
            var forwardHeader = req.headers["x-forwarded-host"];
            if (underscore_1.isArray(forwardHeader)) {
                forwardHeader = forwardHeader[0];
            }
            var host = forwardHeader.split(",")[0];
            baseUrl = req.protocol + "://" + host;
        }
        else if (req.headers["host"]) {
            // Fallback to "HOST" header.
            baseUrl = req.protocol + "://" + req.headers["host"];
        }
        else {
            // Final fallback is to req.hostname, generated by Express. As mentioned
            // above, this won't have a port number and so we attempt to use it last.
            baseUrl = req.protocol + "://" + req.hostname;
        }
        var serviceURL = this.callbackURL || req.originalUrl;
        var resolvedURL = url_1.default.resolve(baseUrl, serviceURL);
        var parsedURL = url_1.default.parse(resolvedURL, true);
        delete parsedURL.query.ticket;
        parsedURL.search = null;
        return url_1.default.format(parsedURL);
    };
    return Strategy;
}(passport_strategy_1.Strategy));
exports.Strategy = Strategy;
exports.default = Strategy;
