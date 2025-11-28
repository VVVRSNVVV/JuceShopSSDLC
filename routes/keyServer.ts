/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

const ENCRYPTION_KEYS_DIR = path.resolve('encryptionkeys')

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file as string

   
    if (!file || file.includes('..') || file.includes('/') || file.includes('\\')) {
      res.status(400)
      return next(new Error('Invalid file name'))
    }


    const safePath = path.resolve(ENCRYPTION_KEYS_DIR, file)


    if (!safePath.startsWith(ENCRYPTION_KEYS_DIR + path.sep)) {
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
