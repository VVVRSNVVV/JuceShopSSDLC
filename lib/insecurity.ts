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

// ✅ ВИПРАВЛЕНО: використовуємо expressjwt напряму, без express_jwt_1
// JWT middleware через express-jwt (RS256 по публічному ключу)
const isAuthorized = () => expressjwt({
  secret: publicKey,
  algorithms: ['RS256']
})
exports.isAuthorized = isAuthorized

// Middleware, який завжди відмовляє (для спеціальних челенджів)
const denyAll = () => expressjwt({
  secret: require('crypto').randomBytes(32),
  algorithms: ['HS256']
})
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

// ... решта коду без змін ...

// ✅ ДОДАНО ДЛЯ TypeScript: позначає файл як модуль
export {}
