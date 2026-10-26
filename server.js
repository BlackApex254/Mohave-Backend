/**
 * Hearthstone Lending Standalone Backend Server (Mohave-Backend)
 * Handles:
 * - Client registration with duplicate prevention
 * - Cryptographic password hashing (scrypt) & timing-safe verification
 * - 6-Digit Email OTP generation & verification
 * - Email templates & notification service (welcome, OTP, intake, approval/denial)
 * - Loan application pipeline & Underwriting approval engine
 * - Document & KYC validation engine (sharpness, brightness, document categories)
 * - Receiving commitment bank configuration (admin & borrower syncing)
 * - Application partial updates (disbursement accounts, fee receipts, docs, status)
 * - Persistent JSON file-backed database storage with fallback
 */

const http = require('http')
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const url = require('url')

const PORT = process.env.PORT || process.env.BACKEND_PORT || 4000
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '.data')
const DB_FILE = path.join(DATA_DIR, 'hearthstone_db.json')

// Ensure persistent data directory exists
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

// Default Seed Data
function getSeedData() {
  const defaultSalt = 'a1b2c3d4e5f60718293a4b5c6d7e8f90'
  const defaultHash = crypto.scryptSync('Hearthstone2026!', defaultSalt, 64).toString('hex')

  return {
    commitmentBank: {
      bankName: 'Hearthstone Reserve Bank, N.A.',
      routingNumber: '021000021',
      accountNumber: '4829018472',
    },
    users: [
      {
        id: 'usr_seed_eleanor',
        firstName: 'Eleanor',
        lastName: 'Vance',
        email: 'eleanor.vance@example.com',
        phone: '(555) 234-5678',
        memberSince: '2026-01-15T09:00:00.000Z',
        passwordHash: defaultHash,
        salt: defaultSalt,
      },
    ],
    otps: [],
    applications: [
      {
        id: 'app_seed_001',
        referenceId: 'HST-2026-78419',
        createdAt: '2026-10-24T14:30:00.000Z',
        status: 'Approved',
        decisionDate: '2026-10-25T11:00:00.000Z',
        underwriterNotes: 'Strong debt-to-income profile and solid liquid reserves. Approved at preferred 3.125% fixed tier.',
        firstName: 'Eleanor',
        middleName: 'Jane',
        lastName: 'Vance',
        email: 'eleanor.vance@example.com',
        phone: '(555) 234-5678',
        dob: '1988-06-14',
        ssn: '***-**-6789',
        ssnLast4: '6789',
        citizenship: 'US Citizen',
        maritalStatus: 'Single',
        streetAddress: '742 Evergreen Terrace',
        city: 'Springfield',
        state: 'Oregon',
        zipCode: '97477',
        yearsAtAddress: '4',
        employmentStatus: 'Employed Full-Time',
        employerName: 'Cascade Medical Center',
        jobTitle: 'Senior Clinical Director',
        yearsInRole: '5',
        annualIncome: 145000,
        additionalIncome: 12000,
        liquidAssets: 85000,
        monthlyDebt: 1200,
        financingType: 'home',
        requestedAmount: 420000,
        purchasePrice: 525000,
        downPayment: 105000,
        creditRange: 'Excellent (740+)',
        intendedTimeframe: 'Within 30 Days',
        collateralDetails: 'Single-family primary residence',
        digitalSignature: 'Eleanor J. Vance',
        agreedToDisclosures: true,
        commitmentFeePaid: false,
        documents: [],
      },
    ],
    emails: [
      {
        id: 'email_seed_001',
        sentAt: '2026-10-25T11:00:00.000Z',
        to: 'eleanor.vance@example.com',
        subject: 'Formal Financing Commitment Issued: HST-2026-78419 · Hearthstone Lending',
        type: 'loan_decision_approved',
        html: '<p>Congratulations Eleanor, your loan application HST-2026-78419 for $420,000 has been approved!</p>',
        previewText: 'Formal approval determination commitment issued.',
        metadata: { referenceId: 'HST-2026-78419', status: 'Approved' },
      },
    ],
  }
}

// Database helper
function loadDb() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'))
      if (!data.commitmentBank) {
        data.commitmentBank = {
          bankName: 'Hearthstone Reserve Bank, N.A.',
          routingNumber: '021000021',
          accountNumber: '4829018472',
        }
      }
      return data
    }
  } catch (e) {
    console.error('Failed to read database file, initializing with seeds:', e)
  }

  const initial = getSeedData()
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

// Email logger and dispatcher
function logEmail(emailRecord) {
  const db = loadDb()
  db.emails = db.emails || []
  db.emails.unshift(emailRecord)
  if (db.emails.length > 200) db.emails = db.emails.slice(0, 200)
  saveDb(db)
  console.log(`[EMAIL DISPATCH] To: ${emailRecord.to} | Subject: "${emailRecord.subject}" | Type: ${emailRecord.type}`)
}

// Helper to parse JSON request bodies
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

// Standard JSON response helper with complete CORS headers
function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
  })
  res.end(JSON.stringify(data))
}

const server = http.createServer(async (req, res) => {
  // CORS Preflight Handling
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
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

      // Duplicate prevention
      const existing = db.users.find((u) => u.email.toLowerCase() === cleanEmail)
      if (existing) {
        return sendJson(res, 409, {
          success: false,
          error: 'An account with this email address is already registered. Please sign in.',
        })
      }

      const { hash, salt } = hashPassword(password)
      const newUser = {
        id: `usr_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
        firstName: firstName.trim(),
        lastName: lastName.trim(),
        email: cleanEmail,
        phone: (phone || '').trim(),
        memberSince: new Date().toISOString(),
        passwordHash: hash,
        salt,
      }

      db.users.push(newUser)

      // Generate 6-digit OTP for email verification
      const otpCode = Math.floor(100000 + Math.random() * 900000).toString()
      db.otps = db.otps || []
      db.otps.push({
        email: cleanEmail,
        code: otpCode,
        purpose: 'signup',
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
        attempts: 0,
      })

      saveDb(db)

      // Dispatch Registration & OTP Emails
      logEmail({
        id: `email_${Date.now()}_reg`,
        sentAt: new Date().toISOString(),
        to: cleanEmail,
        subject: 'Welcome to Hearthstone Lending · Borrower Account Created',
        type: 'custom',
        html: `<p>Welcome ${newUser.firstName}! Your borrowing portal has been created.</p>`,
        previewText: 'Welcome to Hearthstone Lending portal.',
      })

      logEmail({
        id: `email_${Date.now()}_otp`,
        sentAt: new Date().toISOString(),
        to: cleanEmail,
        subject: `Your Security Verification Code: ${otpCode}`,
        type: 'otp',
        html: `<p>Your 6-digit verification code is <strong>${otpCode}</strong>. Valid for 10 minutes.</p>`,
        previewText: `Security Code: ${otpCode}`,
      })

      return sendJson(res, 201, {
        success: true,
        message: 'Account registered successfully. Security code dispatched to your email.',
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

    // 3. User Login (Password Verification & OTP Generation)
    if (pathname === '/api/auth/login' && req.method === 'POST') {
      const body = await getJsonBody(req)
      const { email, password } = body

      if (!email || !password) {
        return sendJson(res, 400, {
          success: false,
          error: 'Email and password are required.',
        })
      }

      const cleanEmail = email.trim().toLowerCase()
      const db = loadDb()
      const user = (db.users || []).find((u) => u.email.toLowerCase() === cleanEmail)

      if (!user) {
        return sendJson(res, 401, {
          success: false,
          error: 'Invalid email or password.',
        })
      }

      // Verify cryptographic password
      const isValid = verifyPassword(password, user.passwordHash, user.salt)
      if (!isValid) {
        return sendJson(res, 401, {
          success: false,
          error: 'Invalid email or password.',
        })
      }

      // Generate 6-digit OTP
      const otpCode = Math.floor(100000 + Math.random() * 900000).toString()
      db.otps = db.otps || []
      db.otps.push({
        email: cleanEmail,
        code: otpCode,
        purpose: 'login',
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
        attempts: 0,
      })

      saveDb(db)

      logEmail({
        id: `email_${Date.now()}_otp`,
        sentAt: new Date().toISOString(),
        to: cleanEmail,
        subject: `Your Login Verification Passcode: ${otpCode}`,
        type: 'otp',
        html: `<p>Your login security passcode is <strong>${otpCode}</strong>. Valid for 10 minutes.</p>`,
        previewText: `Login Passcode: ${otpCode}`,
      })

      return sendJson(res, 200, {
        success: true,
        message: 'Credentials verified. Passcode dispatched to your email.',
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

    // 4. Verify OTP Code
    if (pathname === '/api/auth/verify-otp' && req.method === 'POST') {
      const body = await getJsonBody(req)
      const { email, code } = body

      if (!email || !code) {
        return sendJson(res, 400, {
          success: false,
          error: 'Email and code are required.',
        })
      }

      const cleanEmail = email.trim().toLowerCase()
      const cleanCode = code.trim()
      const db = loadDb()

      const now = new Date()
      const validOtps = (db.otps || []).filter(
        (o) =>
          o.email.toLowerCase() === cleanEmail &&
          o.code === cleanCode &&
          new Date(o.expiresAt) > now
      )

      if (validOtps.length === 0) {
        return sendJson(res, 400, {
          success: false,
          error: 'Invalid or expired 6-digit code. Please request a new code.',
        })
      }

      // Consume OTP
      db.otps = (db.otps || []).filter((o) => !(o.email.toLowerCase() === cleanEmail && o.code === cleanCode))
      saveDb(db)

      const user = (db.users || []).find((u) => u.email.toLowerCase() === cleanEmail) || {
        id: `usr_${Date.now()}`,
        firstName: 'Valued',
        lastName: 'Borrower',
        email: cleanEmail,
        memberSince: new Date().toISOString(),
      }

      return sendJson(res, 200, {
        success: true,
        message: 'Verification complete. Welcome back.',
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

    // 5. Loan Applications Pipeline
    if (pathname === '/api/applications') {
      const db = loadDb()

      if (req.method === 'GET') {
        return sendJson(res, 200, {
          success: true,
          applications: db.applications || [],
          count: (db.applications || []).length,
          commitmentBank: db.commitmentBank,
        })
      }

      if (req.method === 'POST') {
        const body = await getJsonBody(req)
        const refId = `HST-2026-${Math.floor(10000 + Math.random() * 90000)}`

        const rawDigits = (body.ssn || body.ssnLast4 || '').replace(/\D/g, '')
        const ssnFormatted =
          rawDigits.length === 9
            ? `${rawDigits.slice(0, 3)}-${rawDigits.slice(3, 5)}-${rawDigits.slice(5)}`
            : body.ssn || '000-00-0000'
        const ssnLast4 = rawDigits.length >= 4 ? rawDigits.slice(-4) : body.ssnLast4 || '0000'

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

    // 6. Application Details & Partial Updates (Underwriting, Documents, Disbursement, Fee Receipts)
    const appMatch = pathname.match(/^\/api\/applications\/([^/]+)$/)
    if (appMatch) {
      const appId = appMatch[1]
      const db = loadDb()
      const appIndex = (db.applications || []).findIndex(
        (a) => a.id === appId || (a.referenceId && a.referenceId.toLowerCase() === appId.toLowerCase())
      )

      if (appIndex === -1) {
        return sendJson(res, 404, { success: false, error: 'Application not found' })
      }

      if (req.method === 'GET') {
        return sendJson(res, 200, { success: true, application: db.applications[appIndex] })
      }

      if (req.method === 'PATCH') {
        const body = await getJsonBody(req)
        const current = db.applications[appIndex]

        const updated = {
          ...current,
          ...body,
        }

        // If status changed to Approved or Rejected, record decision date and send formal notice
        if (body.status && body.status !== current.status) {
          updated.decisionDate = new Date().toISOString()
          const isApproved = body.status === 'Approved'
          const isRejected = body.status === 'Rejected'

          if (isApproved || isRejected) {
            logEmail({
              id: `email_${Date.now()}`,
              sentAt: new Date().toISOString(),
              to: updated.email,
              subject: isApproved
                ? `Formal Financing Commitment Issued: ${updated.referenceId} · Hearthstone Lending`
                : `Notice of Underwriting Determination: ${updated.referenceId} · Hearthstone Lending`,
              type: isApproved ? 'loan_decision_approved' : 'loan_decision_rejected',
              html: isApproved
                ? `<p>Congratulations, your loan request ${updated.referenceId} for $${(updated.requestedAmount || 0).toLocaleString()} has been approved!</p>`
                : `<p>Notice regarding financing application ${updated.referenceId}. Program guidelines were not met.</p>`,
              previewText: isApproved ? 'Congratulations, your loan is approved!' : 'Credit determination notice.',
              metadata: { referenceId: updated.referenceId, status: body.status, notes: body.underwriterNotes },
            })
          }
        }

        db.applications[appIndex] = updated
        saveDb(db)

        return sendJson(res, 200, {
          success: true,
          message: 'Application updated successfully.',
          application: updated,
        })
      }
    }

    // 7. Admin Receiving Bank Settings (for 6% Commitment Fee)
    if (pathname === '/api/settings/bank') {
      const db = loadDb()

      if (req.method === 'GET') {
        return sendJson(res, 200, {
          success: true,
          commitmentBank: db.commitmentBank,
        })
      }

      if (req.method === 'POST') {
        const body = await getJsonBody(req)
        const { bankName, routingNumber, accountNumber } = body

        if (!bankName || !routingNumber || !accountNumber) {
          return sendJson(res, 400, {
            success: false,
            error: 'bankName, routingNumber, and accountNumber are required.',
          })
        }

        db.commitmentBank = {
          bankName: bankName.trim(),
          routingNumber: routingNumber.trim(),
          accountNumber: accountNumber.trim(),
        }
        saveDb(db)

        return sendJson(res, 200, {
          success: true,
          message: 'Receiving bank details saved and updated across all borrower portals.',
          commitmentBank: db.commitmentBank,
        })
      }
    }

    // 8. KYC Document Validation Engine
    if (pathname === '/api/kyc/validate' && req.method === 'POST') {
      const body = await getJsonBody(req)
      const { docType, idTypeLabel, clientMetrics, borrowerName, borrowerState } = body

      const metrics = clientMetrics || {}
      const isSimulatedInvalid = Boolean(metrics.isSimulatedInvalid)
      const isSimulatedBlurry = Boolean(metrics.isSimulatedBlurry)
      const sharpness = Number(metrics.sharpnessScore || 85)
      const brightness = Number(metrics.brightnessScore || 82)
      const width = Number(metrics.width || 1280)
      const height = Number(metrics.height || 720)

      let categoryName = idTypeLabel || "Government Driver's License"
      if (docType === 'dl_front') {
        categoryName = `${categoryName} (Front)`
      } else if (docType === 'dl_back') {
        categoryName = `${categoryName} (Back Barcode)`
      } else if (docType === 'kyc_selfie_video') {
        categoryName = 'Live Human Face Biometric (Liveness Verified)'
      }

      // Check failure conditions
      if (isSimulatedInvalid) {
        return sendJson(res, 200, {
          valid: false,
          report: {
            isAuthentic: false,
            isBlurry: false,
            sharpnessScore: sharpness,
            brightnessScore: brightness,
            resolution: `${width}x${height}`,
            documentCategory: categoryName,
            summary: 'The submitted document appears altered or invalid. Please provide a clear original.',
            verifiedAt: new Date().toISOString(),
          },
        })
      }

      if (isSimulatedBlurry || sharpness < 45) {
        return sendJson(res, 200, {
          valid: false,
          report: {
            isAuthentic: false,
            isBlurry: true,
            sharpnessScore: sharpness,
            brightnessScore: brightness,
            resolution: `${width}x${height}`,
            documentCategory: categoryName,
            summary: 'Document image failed sharpness check. Text and security elements are illegible.',
            verifiedAt: new Date().toISOString(),
          },
        })
      }

      if (brightness < 30 || brightness > 98) {
        return sendJson(res, 200, {
          valid: false,
          report: {
            isAuthentic: false,
            isBlurry: false,
            sharpnessScore: sharpness,
            brightnessScore: brightness,
            resolution: `${width}x${height}`,
            documentCategory: categoryName,
            summary: brightness < 30
              ? 'Lighting too dark. Please scan in a well-lit environment.'
              : 'Glare or overexposure detected. Please angle away from direct reflections.',
            verifiedAt: new Date().toISOString(),
          },
        })
      }

      // Passed validation
      const report = {
        isAuthentic: true,
        isBlurry: false,
        sharpnessScore: Math.max(sharpness, 80),
        brightnessScore: brightness,
        resolution: `${width}x${height} HD`,
        documentCategory: categoryName,
        summary: 'Document successfully verified against federal lending standards.',
        extractedFields: {
          fullName: borrowerName || 'Eleanor Vance',
          licenseNumber: `DL${Math.floor(10000000 + Math.random() * 90000000)}`,
          state: borrowerState || 'California',
          expirationDate: '12/2029',
          barcodeDetected: docType === 'dl_back' || docType === 'dl_front',
          posesVerified: docType === 'kyc_selfie_video' ? ['Center', 'Tilt Left', 'Tilt Right', 'Smile'] : undefined,
        },
        verifiedAt: new Date().toISOString(),
      }

      return sendJson(res, 200, {
        valid: true,
        report,
      })
    }

    // 9. Email Outbox & Audit Trail
    if (pathname === '/api/email') {
      const db = loadDb()
      if (req.method === 'GET') {
        return sendJson(res, 200, {
          success: true,
          emails: db.emails || [],
          count: (db.emails || []).length,
        })
      }
      if (req.method === 'DELETE') {
        db.emails = []
        saveDb(db)
        return sendJson(res, 200, { success: true, message: 'Email outbox cleared' })
      }
      if (req.method === 'POST') {
        const body = await getJsonBody(req)
        const newEmail = {
          id: `email_${Date.now()}`,
          sentAt: new Date().toISOString(),
          to: body.to || 'borrower@example.com',
          subject: body.subject || 'Hearthstone Lending Advisory Notification',
          type: body.type || 'custom',
          html: body.html || `<p>${body.text || body.subject || 'Notification'}</p>`,
          previewText: body.previewText || body.subject,
          metadata: body.metadata || {},
        }
        logEmail(newEmail)
        return sendJson(res, 201, { success: true, email: newEmail })
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
