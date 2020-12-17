import express from "express";
import passport from "passport";
import { Strategy as CasStrategy } from "../lib/index";

type User = {
  netId: string;
};

passport.use(
  new CasStrategy(
    {
      ssoBaseURL: "https://secure.its.yale.edu/cas",
      serverBaseURL: "http://localhost:9000",
    },
    function (login, done) {
      done(null, {
        netId: login,
      });
    }
  )
);

passport.serializeUser<User, string>(function (user, done) {
  done(null, user.netId);
});

passport.deserializeUser(function (netId, done) {
  done(null, {
    netId,
  });
});

const casLogin = function (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) {
  passport.authenticate("cas", function (err, user) {
    if (err) {
      return next(err);
    }
    if (!user) {
      return next(new Error("CAS auth but no user"));
    }

    req.logIn(user, function (err) {
      if (err) {
        return next(err);
      }

      // TODO: use redirect parameter
      return res.redirect("/check");
    });
  })(req, res, next);
};

export default (app: express.Express) => {
  app.use(passport.initialize());
  app.use(passport.session());

  app.get("/check", (req, res) => {
    if (req.user) {
      res.json({ auth: true, user: req.user });
    } else {
      res.json({ auth: false });
    }
  });

  app.get("/cas", casLogin);
};
