/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../lib/insecurity'

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const fileParam = params.file


    if (!fileParam || typeof fileParam !== 'string') {
      res.status(400)
      return next(new Error('File name is required'))
    }


    if (fileParam.includes('/') || fileParam.includes('\\')) {
      res.status(403)
      return next(new Error('File names cannot contain path separators'))
    }


    const safeFile = security.cutOffPoisonNullByte(fileParam)


    const baseDir = path.resolve('logs')


    const requestedPath = path.resolve(baseDir, safeFile)


    const relative = path.relative(baseDir, requestedPath)
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      res.status(403)
      return next(new Error('Access denied'))
    }


    res.sendFile(requestedPath)
  }
}