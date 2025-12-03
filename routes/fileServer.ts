/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

export function servePublicFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
      verify(file, res, next)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }

  function verify (file: string, res: Response, next: NextFunction) {
    if (!file) {
      res.status(400)
      return next(new Error('File name is required'))
    }

    // 1) спочатку ріжемо null-byte
    let safeFile = security.cutOffPoisonNullByte(file)

    // 2) перевіряємо allowlist по розширеннях
    if (!(endsWithAllowlistedFileType(safeFile) || safeFile === 'incident-support.kdbx')) {
      res.status(403)
      return next(new Error('Only .md and .pdf files are allowed!'))
    }

    // 3) канонічний шлях + перевірка, що файл всередині ftp/
    const baseDir = path.resolve('ftp')
    const requestedPath = path.resolve(baseDir, safeFile)

    const relative = path.relative(baseDir, requestedPath)
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      res.status(403)
      return next(new Error('Access denied'))
    }

    // 4) juice shop challenge logic
    const lower = safeFile.toLowerCase()
    challengeUtils.solveIf(challenges.directoryListingChallenge, () => lower === 'acquisitions.md')
    verifySuccessfulPoisonNullByteExploit(lower)

    // 5) безпечна відповідь
    res.sendFile(requestedPath)
  }

  function verifySuccessfulPoisonNullByteExploit (file: string) {
    challengeUtils.solveIf(challenges.easterEggLevelOneChallenge, () => { return file.toLowerCase() === 'eastere.gg' })
    challengeUtils.solveIf(challenges.forgottenDevBackupChallenge, () => { return file.toLowerCase() === 'package.json.bak' })
    challengeUtils.solveIf(challenges.forgottenBackupChallenge, () => { return file.toLowerCase() === 'coupons_2013.md.bak' })
    challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () => { return file.toLowerCase() === 'suspicious_errors.yml' })

    challengeUtils.solveIf(challenges.nullByteChallenge, () => {
      return challenges.easterEggLevelOneChallenge.solved || challenges.forgottenDevBackupChallenge.solved || challenges.forgottenBackupChallenge.solved ||
        challenges.misplacedSignatureFileChallenge.solved || file.toLowerCase() === 'encrypt.pyc'
    })
  }

  function endsWithAllowlistedFileType (param: string) {
    return utils.endsWith(param, '.md') || utils.endsWith(param, '.pdf')
  }
}
