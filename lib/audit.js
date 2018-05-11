'use strict'

const BB = require('bluebird')

const audit = require('./install/audit.js')
const fs = require('graceful-fs')
const inflateShrinkwrap = BB.promisify(require('./install/inflate-shrinkwrap.js'))
const Installer = require('./install.js').Installer
const lockVerify = require('lock-verify')
const log = require('npmlog')
const npa = require('npm-package-arg')
const npm = require('./npm.js')
const parseJson = require('json-parse-better-errors')
const readShrinkwrap = BB.promisify(require('./install/read-shrinkwrap.js'))
const validate = require('aproba')

const readFile = BB.promisify(fs.readFile)

module.exports = auditCmd

auditCmd.usage =
  'npm audit\n' +
  'npm audit fix\n'

auditCmd.completion = function (opts, cb) {
  const argv = opts.conf.argv.remain

  switch (argv[2]) {
    case 'audit':
      return cb(null, [])
    default:
      return cb(new Error(argv[2] + ' not recognized'))
  }
}

class Auditor extends Installer {
  constructor (where, dryrun, args, opts) {
    super(where, dryrun, args, opts)
    this._deepArgs = (opts && opts.deepArgs) || []
  }

  loadShrinkwrap (cb) {
    return BB.try(() => {
      validate('F', arguments)
      log.silly('install', 'loadShrinkwrap')
      return readShrinkwrap(this.idealTree)
    }).then(() => {
      if (this.idealTree.package._shrinkwrap) {
        this._deepArgs.forEach(arg => {
          arg.reduce((acc, child, i) => {
            if (i === this._deepArgs.length - 1) {
              const spec = npa(child)
              const target = acc.requires.find(n => n.name === spec.name)
              target.version = spec.fetchSpec
              delete target.from
              delete target.resolved
              delete target.requires
              delete target.integrity
            }
            return acc.requires.find(n => n.name === child)
          }, this.idealTree)
        })
        return inflateShrinkwrap(
          this.idealTree,
          this.idealTree.package._shrinkwrap || {}
        )
      }
    }).nodeify(cb)
  }

  // no top level lifecycles on audit
  runPreinstallTopLevelLifecycles (cb) { cb() }
  runPostinstallTopLevelLifecycles (cb) { cb() }
}

function maybeReadFile (name) {
  const file = `${npm.prefix}/${name}`
  return readFile(file)
    .then((data) => {
      try {
        return parseJson(data)
      } catch (ex) {
        ex.code = 'EJSONPARSE'
        throw ex
      }
    })
    .catch({code: 'ENOENT'}, () => null)
    .catch(ex => {
      ex.file = file
      throw ex
    })
}

function auditCmd (args, cb) {
  if (npm.config.get('global')) {
    const err = new Error('`npm audit` does not support testing globals')
    err.code = 'EAUDITGLOBAL'
    throw err
  }
  if (args.length && args[0] !== 'fix') {
    return cb(new Error('Invalid audit subcommand: `' + args[0] + '`\n\nUsage:\n' + auditCmd.usage))
  }
  return BB.all([
    maybeReadFile('npm-shrinkwrap.json'),
    maybeReadFile('package-lock.json'),
    maybeReadFile('package.json')
  ]).spread((shrinkwrap, lockfile, pkgJson) => {
    const sw = shrinkwrap || lockfile
    if (!pkgJson) {
      const err = new Error('No package.json found: Cannot audit a project without a package.json')
      err.code = 'EAUDITNOPJSON'
      throw err
    }
    if (!sw) {
      const err = new Error('Neither npm-shrinkwrap.json nor package-lock.json found: Cannot audit a project without a lockfile')
      err.code = 'EAUDITNOLOCK'
      throw err
    } else if (shrinkwrap && lockfile) {
      log.warn('audit', 'Both npm-shrinkwrap.json and package-lock.json exist, using npm-shrinkwrap.json.')
    }
    const requires = Object.assign(
      {},
      (pkgJson && pkgJson.dependencies) || {},
      (pkgJson && pkgJson.devDependencies) || {}
    )
    return lockVerify(npm.prefix).then(result => {
      if (result.status) return audit.generate(sw, requires)

      const lockFile = shrinkwrap ? 'npm-shrinkwrap.json' : 'package-lock.json'
      const err = new Error(`Errors were found in your ${lockFile}, run  npm install  to fix them.\n    ` +
        result.errors.join('\n    '))
      err.code = 'ELOCKVERIFY'
      throw err
    })
  }).then((auditReport) => {
    return audit.submitForFullReport(auditReport)
  }).catch(err => {
    if (err.statusCode === 404 || err.statusCode >= 500) {
      const ne = new Error(`Your configured registry (${npm.config.get('registry')}) does not support audit requests.`)
      ne.code = 'ENOAUDIT'
      ne.wrapped = err
      throw ne
    }
    throw err
  }).then((auditResult) => {
    if (args[0] === 'fix') {
      const actions = (auditResult.actions || []).reduce((acc, action) => {
        if (action.isMajor) {
          acc.major.add(`${action.module}@${action.target}`)
        } else if (action.action === 'install') {
          acc.install.add(`${action.module}@${action.target}`)
        } else if (action.action === 'update') {
          const name = action.module
          const version = action.target
          action.resolves.forEach(vuln => {
            const modPath = vuln.path.split('>')
            acc.update.add(
              modPath.slice(
                0, modPath.indexOf(name)
              ).concat(`${name}@${version}`).join('>')
            )
          })
        } else if (action.action === 'review') {
          acc.review.add(action)
        }
        return acc
      }, {
        install: new Set(),
        update: new Set(),
        major: new Set(),
        review: new Set()
      })
      return BB.try(() => {
        if (actions.major.size) {
          log.warn('audit', 'some security updates involve breaking changes')
          log.warn('audit', 'and will not be updated automatically.')
          log.warn('audit', 'To update them yourself, run:')
          log.warn('audit', '')
          log.warn('audit', `npm install ${[...actions.major].join(' ')}`)
          log.warn('audit', '')
        }
        if (actions.review.size) {
          log.warn('audit', 'some vulnerabilities require manual review')
          log.warn('audit', 'run `npm audit` to view the full report')
        }
        if (actions.update.size || actions.install.size) {
          log.notice(
            'audit',
            'installing',
            actions.install.size + actions.update.size,
            'updated packages with patched vulnerabilities'
          )
          return BB.fromNode(cb => {
            new Auditor(
              npm.prefix,
              !!npm.config.get('dry-run'),
              [...actions.install],
              {deepArgs: [...actions.update].map(u => u.split('>'))}
            ).run(cb)
          })
        }
      })
    } else {
      const vulns =
        auditResult.metadata.vulnerabilities.low +
        auditResult.metadata.vulnerabilities.moderate +
        auditResult.metadata.vulnerabilities.high +
        auditResult.metadata.vulnerabilities.critical
      if (vulns > 0) process.exitCode = 1
      return audit.printFullReport(auditResult)
    }
  }).asCallback(cb)
}
