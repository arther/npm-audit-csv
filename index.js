#!/usr/bin/env node
const { program } = require('commander');
const fs = require("fs");
const { Parser } = require("json2csv");
const package = require('./package.json');
let data = "";

program
  .version(package.version)
  .option('-o, --output [output]', 'output file')
  .option('-i, --input [input]', 'input file')
  .action((cmd, env) => {
    try {
      if (cmd.input) {
        data = fs.readFileSync(cmd.input).toString();
      }
      if (!data) {
        console.log('No input')
        return process.exit(1)
      }

      generateReport(data, cmd.output)
    } catch (err) {
      console.error('Failed to parse NPM Audit JSON!')
      return process.exit(1)
    }
  });

const getAdvisory = (jsonContent, key) => {
  return jsonContent.advisories
    ? jsonContent.advisories[key.toString()]
    : undefined;
};

const getCVEs = (advisory) => {
  return advisory.cves ? advisory.cves.join(",") : "";
};

const expandPaths = (content, paths) => {
  return paths.map((path) => {
    return {
      ...content,
      path,
    };
  });
};

const resolveParser = (fullJson, resolve) => {
  const advisory = getAdvisory(fullJson, resolve.id);
  const affectedModuleName = advisory.module_name;
  return advisory.findings
    .map((finding) => {
      const map = {
        module: affectedModuleName,
        version: finding.version,
        vulnerability: getCVEs(advisory),
        severity: advisory.severity,
        vulnerability_description: advisory.title,
        vulnerable_versions: advisory.vulnerable_versions,
        patched_versions: advisory.patched_versions,
        overview: advisory.overview,
        recommendation: advisory.recommendation,
        references: advisory.references,
        url: advisory.url,
      };
      return expandPaths(map, finding.paths).flat();
    })
    .flat();
};

const actionParser = (fullJson, action) => {
  let parentModule = action.module;
  const actions = action.resolves
    .map((resolveData) => {
      return resolveParser(fullJson, resolveData);
    })
    .flat();
  return actions.map((action) => {
    return { source: parentModule, ...action };
  });
};

const generateReport = (data, outputFileName = "npm-audit-report.csv") => {
  const fullJson = JSON.parse(data);
  const rows = fullJson.actions
    .map((action) => {
      return actionParser(fullJson, action);
    })
    .flat();
  try {
    const parser = new Parser({});
    const csv = parser.parse(rows);
    fs.writeFileSync(outputFileName, csv);
    console.log("Report generated :)")
  } catch (err) {
    console.error(err);
  }
}
if (process.stdin.isTTY) {
  program.parse(process.argv)
} else {
  process.stdin.setEncoding("utf8");
  process.stdin.on("readable", function () {
    const chunk = this.read();
    if (chunk !== null) {
      data += chunk;
    }
  });

  process.stdin.on("end", function () {
    program.parse(process.argv);
  });
}