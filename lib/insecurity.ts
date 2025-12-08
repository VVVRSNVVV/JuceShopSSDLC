// @ts-nocheck
/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

'use strict'

const fs = require('node:fs')
const crypto = require('node:crypto')
const jwt = require('jsonwebtoken')
const { expressjwt } = require('express-jwt')
const sanitizeHtmlLib = require('sanitize-html')
const sanitizeFilenameLib = require('sanitize-filename')
const utils = require('./utils')
const z85 = require('z85')

// Шляхи до ключів беремо з env, з дефолтами
const jwtPrivateKeyPath = process.env.JWT_PRIVATE_KEY_FILE || 'encryptionkeys/jwtRS256-private.key'
const jwtPublicKeyPath = process.env.JWT_PUBLIC_KEY_FILE || 'encryptionkeys/jwt.pub'

// Публічний ключ (для verify)
const publicKey = fs
  ? fs.readFileSync(jwtPublicKeyPath, 'utf8')
  : 'placeholder-public-key'
exports.publicKey = publicKey

// Приватний ключ (для sign)
let privateKey = 'placeholder-private-key'
try {
  if (fs.existsSync(jwtPrivateKeyPath)) {
    privateKey = fs.readFileSync(jwtPrivateKeyPath, 'utf8')
  } else {
    console.warn('[security] JWT private key file not found at', jwtPrivateKeyPath)
  }
} catch (err) {
  console.error('[security] Failed to load JWT private key:', err)
}

// HMAC secret теж з env
const hmacSecret = process.env.HMAC_SECRET || 'insecure-dev-hmac-secret'

const hash = (data) =>
  crypto.createHash('md5').update(data).digest('hex')
exports.hash = hash

const hmac = (data) =>
  crypto.createHmac('sha256', hmacSecret).update(data).digest('hex')
exports.hmac = hmac

function cutOffPoisonNullByte (str) {
  const nullByte = '%00'
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}
exports.cutOffPoisonNullByte = cutOffPoisonNullByte

// JWT middleware через express-jwt (RS256 по публічному ключу)
const isAuthorized = () => (0, express_jwt_1.expressjwt)({
    secret: exports.publicKey,
    algorithms: ['RS256']
});

exports.isAuthorized = isAuthorized

// Middleware, який завжди відмовляє (для спеціальних челенджів)
const denyAll = () => (0, express_jwt_1.expressjwt)({
    secret: require('crypto').randomBytes(32),
    algorithms: ['HS256']
});

exports.denyAll = denyAll

// Підпис токена приватним ключем (RS256)
const authorize = (user = {}) =>
  jwt.sign(user, privateKey, {
    expiresIn: '6h',
    algorithm: 'RS256'
  })
exports.authorize = authorize

// Перевірка токена з контролем алгоритму
const verify = (token) => {
  if (!token) return false
  try {
    jwt.verify(token, publicKey, { algorithms: ['RS256'] })
    return true
  } catch {
    return false
  }
}
exports.verify = verify

// Декодування токена без перевірки підпису (для нефінкритичних кейсів)
const decode = (token) => {
  if (!token) return undefined
  return jwt.decode(token)
}
exports.decode = decode

// Санітизація HTML / filename
const sanitizeHtml = (html) => sanitizeHtmlLib(html)
exports.sanitizeHtml = sanitizeHtml

const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')
exports.sanitizeLegacy = sanitizeLegacy

const sanitizeFilename = (filename) => sanitizeFilenameLib(filename)
exports.sanitizeFilename = sanitizeFilename

const sanitizeSecure = (html) => {
  const sanitized = sanitizeHtml(html)
  if (sanitized === html) {
    return html
  } else {
    return sanitizeSecure(sanitized)
  }
}
exports.sanitizeSecure = sanitizeSecure

// Сховище аутентифікованих користувачів
const authenticatedUsers = {
  tokenMap: {},
  idMap: {},
  put: function (token, user) {
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  },
  get: function (token) {
    return token ? this.tokenMap[utils.unquote(token)] : undefined
  },
  tokenOf: function (user) {
    return user ? this.idMap[user.id] : undefined
  },
  from: function (req) {
    const token = utils.jwtFrom(req)
    return token ? this.get(token) : undefined
  },
  updateFrom: function (req, user) {
    const token = utils.jwtFrom(req)
    this.put(token, user)
  }
}
exports.authenticatedUsers = authenticatedUsers

const userEmailFrom = ({ headers }) => {
  return headers ? headers['x-user-email'] : undefined
}
exports.userEmailFrom = userEmailFrom

const generateCoupon = (discount, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon)
}
exports.generateCoupon = generateCoupon

const discountFromCoupon = (coupon) => {
  if (!coupon) {
    return undefined
  }
  const decoded = z85.decode(coupon)
  if (decoded && (hasValidFormat(decoded.toString()) != null)) {
    const parts = decoded.toString().split('-')
    const validity = parts[0]
    if (utils.toMMMYY(new Date()) === validity) {
      const discount = parts[1]
      return parseInt(discount)
    }
  }
}
exports.discountFromCoupon = discountFromCoupon

function hasValidFormat (coupon) {
  return coupon.match(/(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{2}/)
}

// vuln-code-snippet start redirectCryptoCurrencyChallenge redirectChallenge
const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])
exports.redirectAllowlist = redirectAllowlist

const isRedirectAllowed = (rawUrl) => {
  if (typeof rawUrl !== 'string') {
    return false
  }

  const url = rawUrl.trim()
  if (!url) {
    return false
  }

  return redirectAllowlist.has(url)
}
exports.isRedirectAllowed = isRedirectAllowed
// vuln-code-snippet end redirectCryptoCurrencyChallenge redirectChallenge

const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
}
exports.roles = roles

const deluxeToken = (email) => {
  const h = crypto.createHmac('sha256', privateKey)
  return h.update(email + roles.deluxe).digest('hex')
}
exports.deluxeToken = deluxeToken

const isAccounting = () => {
  return (req, res, next) => {
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken && decodedToken.data && decodedToken.data.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}
exports.isAccounting = isAccounting

const isDeluxe = (req) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken &&
    decodedToken.data &&
    decodedToken.data.role === roles.deluxe &&
    decodedToken.data.deluxeToken &&
    decodedToken.data.deluxeToken === deluxeToken(decodedToken.data.email)
}
exports.isDeluxe = isDeluxe

const isCustomer = (req) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken && decodedToken.data && decodedToken.data.role === roles.customer
}
exports.isCustomer = isCustomer

const appendUserId = () => {
  return (req, res, next) => {
    try {
      req.body.UserId = authenticatedUsers.tokenMap[utils.jwtFrom(req)].data.id
      next()
    } catch (error) {
      res.status(401).json({ status: 'error', message: error })
    }
  }
}
exports.appendUserId = appendUserId

const updateAuthenticatedUsers = () =>
  (req, res, next) => {
    const token = req.cookies.token || utils.jwtFrom(req)
    if (token) {
      try {
        const decoded = jwt.verify(token, publicKey, {
          algorithms: ['RS256']
        })

        if (authenticatedUsers.get(token) === undefined) {
          authenticatedUsers.put(token, decoded)
          res.cookie('token', token)
        }
      } catch {
        // невалідний / протермінований токен — ігноруємо
      }
    }
    next()
  }
exports.updateAuthenticatedUsers = updateAuthenticatedUsers
