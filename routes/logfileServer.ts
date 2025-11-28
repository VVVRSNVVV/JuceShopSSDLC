/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

const LOGS_DIR = path.resolve('logs')

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file as string


    if (!file || file.includes('..') || file.includes('/') || file.includes('\\')) {
      res.status(400)
      return next(new Error('Invalid file name'))
    }


    const safePath = path.resolve(LOGS_DIR, file)


    if (!safePath.startsWith(LOGS_DIR + path.sep)) {
      res.status(403)
      return next(new Error('Access denied'))
    }


    res.sendFile(safePath, (err) => {
      if (err) {
        next(err)
      }
    })
  }
}