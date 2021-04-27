#!/usr/bin/env node
const fs = require("fs");
const { Parser } = require("json2csv");
let data = "";

process.stdin.resume();
process.stdin.setEncoding("utf8");
process.stdin.on("readable", function () {
  const chunk = this.read();
  if (chunk !== null) {
    data += chunk;
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

process.stdin.on("end", function () {
  const fullJson = JSON.parse(data);
  const rows = fullJson.actions
    .map((action) => {
      return actionParser(fullJson, action);
    })
    .flat();
  try {
    const parser = new Parser({});
    const csv = parser.parse(rows);
    fs.writeFileSync("npm-audit-report.csv", csv);
  } catch (err) {
    console.error(err);
  }
});
