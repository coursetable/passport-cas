import express from "express";
import passport from "passport";
import { Strategy as CasStrategy } from "../lib/index";

type User = {
  netId: string;
};

passport.use(
  new CasStrategy(
    {
      version: "CAS2.0",
      ssoBaseURL: "https://secure.its.yale.edu/cas",
    },
    function (profile, done) {
      console.log("verify user: ", profile);
      done(null, {
        netId: profile.user,
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

      if (req.query.redirect) {
        return res.redirect(req.query.redirect as string);
      }

      return res.redirect("/check?nothing");
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
