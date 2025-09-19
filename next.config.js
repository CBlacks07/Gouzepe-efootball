// next.config.js
const path = require('path');
module.exports = {
  outputFileTracingRoot: path.join(__dirname), // ajuste si monorepo: path.join(__dirname, '../../')
};
