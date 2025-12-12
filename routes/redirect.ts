/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function performRedirect () {
  return (req: Request, res: Response, next: NextFunction) => {
    const toParam = req.query.to


    if (typeof toParam !== 'string') {
      return res.redirect('/')
    }

    const toUrl = toParam.trim()
    if (!toUrl) {
      return res.redirect('/')
    }

  
    challengeUtils.solveIf(
      challenges.redirectCryptoCurrencyChallenge,
      () => {
        return (
          toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW' ||
          toUrl === 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' ||
          toUrl === 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6'
        )
      }
    )

    challengeUtils.solveIf(
      challenges.redirectChallenge,
      () => isUnintendedRedirect(toUrl)
    )


    try {
   
      if (toUrl.startsWith('/')) {
        return res.redirect(toUrl)
      }

      const base = `${req.protocol}://${req.get('host')}`
      const parsed = new URL(toUrl, base)

      const currentHost = req.get('host')
      if (parsed.host !== currentHost) {
  
        return res.status(400).send('Invalid redirect URL')
      }

      const safeTarget = parsed.pathname + parsed.search + parsed.hash
      return res.redirect(safeTarget)
    } catch (err) {
     
      return res.status(400).send('Invalid redirect URL')
    }
  }
}

function isUnintendedRedirect (toUrl: string) {
  let unintended = true
  for (const allowedUrl of security.redirectAllowlist) {
    unintended = unintended && !utils.startsWith(toUrl, allowedUrl)
  }
  return unintended
}