var chalk = require('chalk');

var buildPolicyString = require('./lib/utils')['buildPolicyString'];

var CSP_SELF        = "'self'";
var CSP_NONE        = "'none'";
var REPORT_PATH     = '/csp-report';

var CSP_HEADER              = 'Content-Security-Policy';
var CSP_HEADER_REPORT_ONLY  = 'Content-Security-Policy-Report-Only';

var CSP_REPORT_URI          = 'report-uri';
var CSP_FRAME_ANCESTORS     = 'frame-ancestors';
var CSP_SANDBOX             = 'sandbox';

var META_UNSUPPORTED_DIRECTIVES = [
  CSP_REPORT_URI,
  CSP_FRAME_ANCESTORS,
  CSP_SANDBOX,
];

var unsupportedDirectives = function(policyObject) {
  return META_UNSUPPORTED_DIRECTIVES.filter(function(name) {
    return policyObject && (name in policyObject);
  });
}

module.exports = {
  name: 'ember-cli-content-security-policy',

  config: function(/* environment, appConfig */) {
    return {
      contentSecurityPolicyHeader: CSP_HEADER_REPORT_ONLY,
      contentSecurityPolicy: {
        'default-src':  [CSP_NONE],
        'script-src':   [CSP_SELF],
        'font-src':     [CSP_SELF],
        'connect-src':  [CSP_SELF],
        'img-src':      [CSP_SELF],
        'style-src':    [CSP_SELF],
        'media-src':    [CSP_SELF]
      }
    };
  },

  serverMiddleware: function(config) {
    var app = config.app;
    var options = config.options;
    var project = options.project;

    app.use(function(req, res, next) {
      var appConfig = project.config(options.environment);

      var header = appConfig.contentSecurityPolicyHeader;
      var headerConfig = appConfig.contentSecurityPolicy;

      if (options.liveReload) {
        ['localhost', '0.0.0.0'].forEach(function(host) {
          var liveReloadHost = host + ':' + options.liveReloadPort;
          headerConfig['connect-src'] += (' ' + 'ws://' + liveReloadHost);
          headerConfig['script-src'] += (' ' + liveReloadHost);
        });
      }

      if (header.indexOf('Report-Only') !== -1 && !('report-uri' in headerConfig)) {
        var normalizedHost = options.host === '0.0.0.0' ? 'localhost' : options.host;
        var emberCliServer = 'http://' + normalizedHost + ':' + options.port + REPORT_PATH
        headerConfig['connect-src'] += (' ' + emberCliServer);
        headerConfig['report-uri'] = emberCliServer;
      }

      var headerValue = buildPolicyString(headerConfig);

      if (!header || !headerValue) {
        next();
        return;
      }

      // clear existing headers before setting ours
      res.removeHeader(CSP_HEADER);
      res.removeHeader('X-' + CSP_HEADER);

      res.removeHeader(CSP_HEADER_REPORT_ONLY);
      res.removeHeader('X-' + CSP_HEADER_REPORT_ONLY);

      res.setHeader(header, headerValue);
      res.setHeader('X-' + header, headerValue);

      next();
    });

    var bodyParser = require('body-parser');
    app.use(REPORT_PATH, bodyParser.json({ type: 'application/csp-report' }));
    app.use(REPORT_PATH, bodyParser.json({ type: 'application/json' }));
    app.use(REPORT_PATH, function(req, res, next) {
      console.log(chalk.red('Content Security Policy violation:') + '\n\n' + JSON.stringify(req.body, null, 2));
      res.send({ status:'ok' });
    });
  },

  contentFor: function(type, appConfig) {
    if ((type === 'head' && appConfig.contentSecurityPolicyMeta)) {
      var policyObject = appConfig.contentSecurityPolicy;
      var policyString = buildPolicyString(policyObject);

      unsupportedDirectives(policyObject).forEach(function(name) {
        var msg = 'CSP deliverd via meta does not support `' + name + '`, ' +
                  'per the W3C recommendation.';
        console.log(chalk.yellow(msg));
      });

      if (!policyString) {
        console.log(chalk.yellow('CSP via meta tag enabled but no policy exist.'));
      } else {
        return '<meta http-equiv="' + CSP_HEADER + '" content="' + policyString + '">';
      }
    }
  }
};
