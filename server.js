/**
 * Hearthstone Lending Standalone Backend Server
 * Handles:
 * - Client registration with duplicate prevention
 * - Cryptographic password hashing (scrypt) & verification
 * - 6-Digit Email OTP generation & verification
 * - Email templates & notification service (welcome, OTP, intake, approval/denial)
 * - Loan application pipeline & Underwriting approval engine
 * - Persistent JSON file-backed database storage
 */

const http = require('http')
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const url = require('url')

const PORT = process.env.BACKEND_PORT || 4000
const DATA_DIR = path.join(__dirname, '..', '.data')
const DB_FILE = path.join(DATA_DIR, 'hearthstone_db.json')

// Ensure data folder exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true })
}

// Password hashing utility using crypto.scryptSync
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex')
  const hash = crypto.scryptSync(password, salt, 64).toString('hex')
  return { hash, salt }
}

function verifyPassword(password, storedHash, storedSalt) {
  try {
    const testHash = crypto.scryptSync(password, storedSalt, 64).toString('hex')
    const keyA = Buffer.from(testHash, 'hex')
    const keyB = Buffer.from(storedHash, 'hex')
    if (keyA.length !== keyB.length) return false
    return crypto.timingSafeEqual(keyA, keyB)
  } catch {
    return false
  }
}

// Database helper
function loadDb() {
  try {
    if (fs.existsSync(DB_FILE)) {
      return JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'))
    }
  } catch (e) {
    console.error('Failed to read database file:', e)
  }

  const initial = {
    users: [],
    applications: [],
    otps: [],
    emails: [],
  }
  saveDb(initial)
  return initial
}

function saveDb(db) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf-8')
  } catch (e) {
    console.error('Failed to persist database file:', e)
  }
}

// Email logger
function logEmail(emailRecord) {
  const db = loadDb()
  db.emails = db.emails || []
  db.emails.unshift(emailRecord)
  if (db.emails.length > 100) db.emails = db.emails.slice(0, 100)
  saveDb(db)
  console.log(`[EMAIL DISPATCH] Sent to: ${emailRecord.to} | Subject: "${emailRecord.subject}" | Type: ${emailRecord.type}`)
}

// Request helper to parse JSON body
function getJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = ''
    req.on('data', (chunk) => {
      body += chunk
    })
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {})
      } catch (err) {
        reject(err)
      }
    })
    req.on('error', reject)
  })
}

// Response helper
function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  })
  res.end(JSON.stringify(data))
}

const server = http.createServer(async (req, res) => {
  // CORS Preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    })
    res.end()
    return
  }

  const parsedUrl = url.parse(req.url, true)
  const pathname = parsedUrl.pathname
  const query = parsedUrl.query

  try {
    // Health checks
    if (pathname === '/health' || pathname === '/api/health') {
      return sendJson(res, 200, {
        status: 'healthy',
        service: 'Hearthstone Lending Standalone Backend',
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
      })
    }

    // 1. Check Email Exists
    if (pathname === '/api/auth/check-email' && req.method === 'GET') {
      const email = (query.email || '').trim().toLowerCase()
      const db = loadDb()
      const exists = (db.users || []).some((u) => u.email.toLowerCase() === email)
      return sendJson(res, 200, { exists })
    }

    // 2. Register Client (Duplicate Prevention & Password Hashing)
    if (pathname === '/api/auth/register' && req.method === 'POST') {
      const body = await getJsonBody(req)
      const { firstName, lastName, email, phone, password } = body

      if (!firstName || !lastName || !email || !password) {
        return sendJson(res, 400, {
          success: false,
          error: 'First name, last name, email, and password are required.',
        })
      }

      if (password.length < 6) {
        return sendJson(res, 400, {
          success: false,
          error: 'Password must be at least 6 characters long.',
        })
      }

      const cleanEmail = email.trim().toLowerCase()
      const db = loadDb()
      db.users = db.users || []

      // PREVENT DUPLICATE SIGN-UP
      const existing = db.users.find((u) => u.email.toLowerCase() === cleanEmail)
      if (existing) {
        return sendJson(res, 409, {
          success: false,
          error: 'An account with this email address already exists. Please sign in or use a different email.',
        })
      }

      const { hash, salt } = hashPassword(password)
      const newUser = {
        id: `usr_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
        firstName: firstName.trim(),
        lastName: lastName.trim(),
        email: cleanEmail,
        phone: (phone || '').trim(),
        passwordHash: hash,
        salt,
        memberSince: new Date().getFullYear().toString(),
        emailVerified: false,
        createdAt: new Date().toISOString(),
      }

      db.users.push(newUser)

      // Generate 6-digit OTP
      const otpCode = Math.floor(100000 + Math.random() * 900000).toString()
      db.otps = (db.otps || []).filter((o) => !(o.email === cleanEmail && o.purpose === 'signup'))
      db.otps.push({
        email: cleanEmail,
        code: otpCode,
        purpose: 'signup',
        expiresAt: Date.now() + 10 * 60 * 1000,
      })
      saveDb(db)

      // Log & dispatch OTP email
      logEmail({
        id: `email_${Date.now()}`,
        sentAt: new Date().toISOString(),
        to: cleanEmail,
        subject: `Your Hearthstone Passcode: ${otpCode}`,
        type: 'otp',
        html: `<p>Your Hearthstone security passcode is <strong>${otpCode}</strong>. Valid for 10 minutes.</p>`,
        previewText: `Your security code is ${otpCode}.`,
        metadata: { otp: otpCode, purpose: 'signup' },
      })

      return sendJson(res, 201, {
        success: true,
        message: 'Account registered. Security passcode dispatched.',
        email: cleanEmail,
        user: {
          id: newUser.id,
          firstName: newUser.firstName,
          lastName: newUser.lastName,
          email: newUser.email,
          phone: newUser.phone,
          memberSince: newUser.memberSince,
        },
      })
    }

    // 3. Login
    if (pathname === '/api/auth/login' && req.method === 'POST') {
      const body = await getJsonBody(req)
      const { email, password } = body

      if (!email || !password) {
        return sendJson(res, 400, { success: false, error: 'Email and password required.' })
      }

      const cleanEmail = email.trim().toLowerCase()
      const db = loadDb()
      const user = (db.users || []).find((u) => u.email.toLowerCase() === cleanEmail)

      if (!user) {
        return sendJson(res, 404, {
          success: false,
          error: 'No account found with this email address. Please register.',
        })
      }

      const valid = verifyPassword(password, user.passwordHash, user.salt)
      if (!valid) {
        return sendJson(res, 401, {
          success: false,
          error: 'Incorrect password. Please verify and try again.',
        })
      }

      const otpCode = Math.floor(100000 + Math.random() * 900000).toString()
      db.otps = (db.otps || []).filter((o) => !(o.email === cleanEmail && o.purpose === 'login'))
      db.otps.push({
        email: cleanEmail,
        code: otpCode,
        purpose: 'login',
        expiresAt: Date.now() + 10 * 60 * 1000,
      })
      saveDb(db)

      logEmail({
        id: `email_${Date.now()}`,
        sentAt: new Date().toISOString(),
        to: cleanEmail,
        subject: `Your Hearthstone Login Passcode: ${otpCode}`,
        type: 'otp',
        html: `<p>Your Hearthstone login passcode is <strong>${otpCode}</strong>. Valid for 10 minutes.</p>`,
        previewText: `Your login passcode is ${otpCode}.`,
        metadata: { otp: otpCode, purpose: 'login' },
      })

      return sendJson(res, 200, {
        success: true,
        message: 'Password verified. Passcode sent to email.',
        email: cleanEmail,
        user: {
          id: user.id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          phone: user.phone,
          memberSince: user.memberSince,
        },
      })
    }

    // 4. Verify OTP
    if (pathname === '/api/auth/verify-otp' && req.method === 'POST') {
      const body = await getJsonBody(req)
      const { email, code, purpose } = body

      if (!email || !code) {
        return sendJson(res, 400, { success: false, error: 'Email and code are required.' })
      }

      const cleanEmail = email.trim().toLowerCase()
      const cleanCode = code.replace(/\s+/g, '')
      const db = loadDb()
      const record = (db.otps || []).find(
        (o) => o.email.toLowerCase() === cleanEmail && o.purpose === (purpose || 'signup')
      )

      if (!record) {
        return sendJson(res, 400, {
          success: false,
          error: 'No active verification code found. Please request a new code.',
        })
      }

      if (Date.now() > record.expiresAt) {
        db.otps = db.otps.filter((o) => o !== record)
        saveDb(db)
        return sendJson(res, 400, {
          success: false,
          error: 'Security passcode has expired. Please request a new code.',
        })
      }

      if (record.code !== cleanCode) {
        return sendJson(res, 400, {
          success: false,
          error: 'Invalid verification passcode. Please try again.',
        })
      }

      // Valid: clear OTP
      db.otps = db.otps.filter((o) => o !== record)
      const user = (db.users || []).find((u) => u.email.toLowerCase() === cleanEmail)
      if (user) user.emailVerified = true
      saveDb(db)

      return sendJson(res, 200, {
        success: true,
        message: 'Passcode verified successfully.',
        user: user
          ? {
              id: user.id,
              firstName: user.firstName,
              lastName: user.lastName,
              email: user.email,
              phone: user.phone,
              memberSince: user.memberSince,
            }
          : null,
      })
    }

    // 5. Applications: List & Create
    if (pathname === '/api/applications') {
      const db = loadDb()
      if (req.method === 'GET') {
        let apps = db.applications || []
        if (query.email) {
          const target = query.email.toLowerCase()
          apps = apps.filter((a) => a.email.toLowerCase() === target)
        }
        return sendJson(res, 200, { success: true, applications: apps, count: apps.length })
      }

      if (req.method === 'POST') {
        const body = await getJsonBody(req)
        const refId = `HST-2026-${Math.floor(10000 + Math.random() * 90000)}`
        const rawDigits = (body.ssn || body.ssnLast4 || '').replace(/\D/g, '')
        const ssnFormatted =
          rawDigits.length === 9
            ? `${rawDigits.slice(0, 3)}-${rawDigits.slice(3, 5)}-${rawDigits.slice(5)}`
            : body.ssn || '000-00-0000'
        const ssnLast4 = rawDigits.length >= 4 ? rawDigits.slice(-4) : (body.ssnLast4 || '0000')

        const newApp = {
          ...body,
          ssn: ssnFormatted,
          ssnLast4,
          id: `app_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
          referenceId: refId,
          createdAt: new Date().toISOString(),
          status: 'Pending',
        }

        db.applications = db.applications || []
        db.applications.unshift(newApp)
        saveDb(db)

        // Dispatch application receipt notice
        logEmail({
          id: `email_${Date.now()}`,
          sentAt: new Date().toISOString(),
          to: newApp.email,
          subject: `Application Logged: ${newApp.referenceId} · Hearthstone Underwriting`,
          type: 'application_received',
          html: `<p>Application ${newApp.referenceId} received and under review. Decision commitment: 1-3 business days.</p>`,
          previewText: `File ${newApp.referenceId} logged in underwriting.`,
          metadata: { referenceId: newApp.referenceId, amount: newApp.requestedAmount },
        })

        return sendJson(res, 201, {
          success: true,
          message: 'Application received and routed to Underwriting.',
          application: newApp,
        })
      }
    }

    // 6. Application Details & Underwriting Decision (Point of Approval)
    const appMatch = pathname.match(/^\/api\/applications\/([^/]+)$/)
    if (appMatch) {
      const appId = appMatch[1]
      const db = loadDb()
      const appIndex = (db.applications || []).findIndex(
        (a) => a.id === appId || a.referenceId.toLowerCase() === appId.toLowerCase()
      )

      if (appIndex === -1) {
        return sendJson(res, 404, { success: false, error: 'Application not found' })
      }

      if (req.method === 'GET') {
        return sendJson(res, 200, { success: true, application: db.applications[appIndex] })
      }

      if (req.method === 'PATCH') {
        const body = await getJsonBody(req)
        const { status, underwriterNotes, rate } = body

        if (!status || !['Pending', 'Approved', 'Rejected'].includes(status)) {
          return sendJson(res, 400, { success: false, error: 'Valid status required' })
        }

        const current = db.applications[appIndex]
        const updated = {
          ...current,
          status,
          decisionDate: new Date().toISOString(),
          underwriterNotes: underwriterNotes !== undefined ? underwriterNotes : current.underwriterNotes,
        }
        db.applications[appIndex] = updated
        saveDb(db)

        // Point of Approval: Dispatch decision notice
        if (status === 'Approved' || status === 'Rejected') {
          const isApproved = status === 'Approved'
          logEmail({
            id: `email_${Date.now()}`,
            sentAt: new Date().toISOString(),
            to: updated.email,
            subject: isApproved
              ? `Formal Financing Commitment Issued: ${updated.referenceId} · Hearthstone Lending`
              : `Notice of Underwriting Determination: ${updated.referenceId} · Hearthstone Lending`,
            type: 'status_update',
            html: isApproved
              ? `<p>Congratulations, your loan request ${updated.referenceId} for $${(updated.requestedAmount || 0).toLocaleString()} has been approved!</p>`
              : `<p>Notice regarding financing application ${updated.referenceId}. Program guidelines were not met.</p>`,
            previewText: isApproved ? 'Congratulations, your loan is approved!' : 'Credit determination notice.',
            metadata: { referenceId: updated.referenceId, status, rate, notes: underwriterNotes },
          })
        }

        return sendJson(res, 200, {
          success: true,
          message: `Application updated to ${status}. Decision notice dispatched.`,
          application: updated,
        })
      }
    }

    // 7. Email Outbox
    if (pathname === '/api/email') {
      const db = loadDb()
      if (req.method === 'GET') {
        return sendJson(res, 200, { success: true, emails: db.emails || [], count: (db.emails || []).length })
      }
      if (req.method === 'DELETE') {
        db.emails = []
        saveDb(db)
        return sendJson(res, 200, { success: true, message: 'Email outbox cleared' })
      }
    }

    // Fallback 404
    sendJson(res, 404, { success: false, error: 'Endpoint not found' })
  } catch (err) {
    console.error('Server error handling request:', err)
    sendJson(res, 500, { success: false, error: 'Internal server error' })
  }
})

server.listen(PORT, () => {
  console.log(`Hearthstone Lending Standalone Backend listening on port ${PORT}`)
})
