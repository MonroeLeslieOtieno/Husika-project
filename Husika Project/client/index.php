<?php
session_start();

require_once 'database.php';

$error = '';
$success = '';

/*
|--------------------------------------------------------------------------
| ONE-TIME SUCCESS / ERROR MESSAGES
|--------------------------------------------------------------------------
*/
if (isset($_SESSION['success_message'])) {
    $success = $_SESSION['success_message'];
    unset($_SESSION['success_message']);
}

if (isset($_SESSION['error_message'])) {
    $error = $_SESSION['error_message'];
    unset($_SESSION['error_message']);
}


/*
|--------------------------------------------------------------------------
| HANDLE LOGIN
|--------------------------------------------------------------------------
*/
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'login') {

    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($email === '' || $password === '') {

        $_SESSION['error_message'] = 'Please enter your email and password.';
        header('Location: index.php#login');
        exit;

    } else {

        try {

            $stmt = $pdo->prepare("
                SELECT id, name, email, password_hash, role, status
                FROM users
                WHERE email = ?
                LIMIT 1
            ");

            $stmt->execute([$email]);

            $user = $stmt->fetch();

            if (!$user) {

                $_SESSION['error_message'] = 'Invalid email or password.';
                header('Location: index.php#login');
                exit;

            } elseif ($user['status'] !== 'active') {

                $_SESSION['error_message'] = 'Your account is not active.';
                header('Location: index.php#login');
                exit;

            } elseif (!password_verify($password, $user['password_hash'])) {

                $_SESSION['error_message'] = 'Invalid email or password.';
                header('Location: index.php#login');
                exit;

            } else {

                session_regenerate_id(true);

                $_SESSION['user_id'] = $user['id'];
                $_SESSION['name'] = $user['name'];
                $_SESSION['email'] = $user['email'];
                $_SESSION['role'] = $user['role'];
                $_SESSION['logged_in'] = true;

                // Update last login
                $update = $pdo->prepare("
                    UPDATE users
                    SET last_login = CURRENT_TIMESTAMP
                    WHERE id = ?
                ");

                $update->execute([$user['id']]);

                if ($user['role'] === 'admin') {

                    header('Location: admin.php');
                    exit;

                } else {

                    header('Location: dashboard.php');
                    exit;

                }
            }

        } catch (PDOException $e) {

            $_SESSION['error_message'] = 'Unable to process login. Please try again.';
            header('Location: index.php#login');
            exit;
        }
    }
}


/*
|--------------------------------------------------------------------------
| HANDLE MEMBER REGISTRATION
|--------------------------------------------------------------------------
*/
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'register') {

    $firstName = trim($_POST['first_name'] ?? '');
    $lastName = trim($_POST['last_name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $phone = trim($_POST['phone'] ?? '');
    $group = trim($_POST['group_name'] ?? '');
    $password = $_POST['password'] ?? '';

    $name = trim($firstName . ' ' . $lastName);

    if (
        $firstName === '' ||
        $lastName === '' ||
        $email === '' ||
        $password === ''
    ) {

        $_SESSION['error_message'] = 'Please fill in all required registration fields.';
        header('Location: index.php#login');
        exit;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {

        $_SESSION['error_message'] = 'Please enter a valid email address.';
        header('Location: index.php#login');
        exit;
    }

    if (strlen($password) < 6) {

        $_SESSION['error_message'] = 'Password must contain at least 6 characters.';
        header('Location: index.php#login');
        exit;
    }

    try {

        // Check whether email already exists
        $check = $pdo->prepare("
            SELECT id
            FROM users
            WHERE email = ?
            LIMIT 1
        ");

        $check->execute([$email]);

        if ($check->fetch()) {

            $_SESSION['error_message'] = 'An account with this email already exists. Please log in instead.';
            header('Location: index.php#login');
            exit;
        }

        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

        /*
         * The original users table only contains:
         * id, name, email, password_hash, role, status,
         * created_at and last_login.
         *
         * Therefore the member's phone and group are not inserted
         * into the users table unless those columns exist.
         */
        $stmt = $pdo->prepare("
            INSERT INTO users
            (name, email, password_hash, role, status)
            VALUES (?, ?, ?, 'member', 'active')
        ");

        $stmt->execute([
            $name,
            $email,
            $passwordHash
        ]);

        $_SESSION['success_message'] =
            'Registration successful! Your Husika Events member account has been created. You can now log in.';

        header('Location: index.php#login');
        exit;

    } catch (PDOException $e) {

        $_SESSION['error_message'] =
            'Registration failed. Please try again.';

        header('Location: index.php#login');
        exit;
    }
}


/*
|--------------------------------------------------------------------------
| HANDLE INCIDENT REPORT
|--------------------------------------------------------------------------
*/
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'report') {

    $incidentType = trim($_POST['incident_type'] ?? '');
    $location = trim($_POST['location'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $reporterName = trim($_POST['reporter_name'] ?? '');
    $phone = trim($_POST['phone'] ?? '');

    if ($incidentType === '' || $description === '') {

        $_SESSION['error_message'] =
            'Please select the incident type and describe what happened.';

        header('Location: index.php#report');
        exit;
    }

    try {

        $stmt = $pdo->prepare("
            INSERT INTO reports
            (
                incident_type,
                location,
                description,
                reporter_name,
                phone,
                status
            )
            VALUES (?, ?, ?, ?, ?, 'Open')
        ");

        $stmt->execute([
            $incidentType,
            $location,
            $description,
            $reporterName,
            $phone
        ]);

        $_SESSION['success_message'] =
            'Your incident report has been submitted successfully. Thank you for speaking up. Our team will review it confidentially.';

        header('Location: index.php#report');
        exit;

    } catch (PDOException $e) {

        $_SESSION['error_message'] =
            'We could not submit your report. Please try again.';

        header('Location: index.php#report');
        exit;
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Husika Events – Give Hope, Give Love, Give Back</title>

  <link rel="stylesheet" href="styles.css" />

  <link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700;800;900&family=Playfair+Display:wght@700;900&display=swap" rel="stylesheet" />
</head>

<body>

  <!-- ===== TOP BAR ===== -->
  <div class="topbar">
    <span>📞 WhatsApp: <strong>+254 721 110 572</strong></span>
    <span>Give Hope · Give Love · Give Back</span>
  </div>


  <!-- ===== NAVBAR ===== -->
  <header class="navbar" id="navbar">

    <div class="nav-brand">
      <span class="brand-husika">Husika</span>
      <span class="brand-events">EVENTS</span>
    </div>

    <nav class="nav-links" id="nav-links">

      <a href="#home" class="nav-link active">Home</a>

      <a href="#about" class="nav-link">About</a>

      <a href="#activities" class="nav-link">Activities</a>

      <a href="#report" class="nav-link nav-link--report">Report</a>

      <a href="#gallery" class="nav-link">Gallery</a>

      <a href="#contact" class="nav-link">Contact</a>

      <a href="#login" class="nav-link nav-link--login">
        Login / Join
      </a>

    </nav>

    <button class="hamburger" id="hamburger" aria-label="Toggle menu">
      <span></span>
      <span></span>
      <span></span>
    </button>

  </header>


  <!-- ===== HERO ===== -->
  <section class="hero" id="home">

    <div class="hero-content">

      <p class="hero-eyebrow">Husika Events</p>

      <h1 class="hero-headline">
        Speak Up.<br>
        Protect a Child.
      </h1>

      <p class="hero-sub">
        We are a community of changemakers committed to child safety, education, and dignified living across Kenya.
      </p>

      <div class="hero-actions">

        <a href="#report" class="btn btn--primary">
          Report an Incident
        </a>

        <a href="#about" class="btn btn--outline">
          Learn More
        </a>

      </div>

    </div>


    <div class="hero-badges">

      <div class="badge">
        <span class="badge-icon">🛡️</span>
        <span>Child Safety</span>
      </div>

      <div class="badge">
        <span class="badge-icon">🤝</span>
        <span>Community</span>
      </div>

      <div class="badge">
        <span class="badge-icon">📣</span>
        <span>Speak Up</span>
      </div>

      <div class="badge">
        <span class="badge-icon">❤️</span>
        <span>Give Back</span>
      </div>

    </div>

  </section>


  <!-- ===== ALERT STRIP ===== -->
  <div class="alert-strip">

    <p>
      <strong>You Are Not Alone — Help Is Available.</strong>
      Text/WhatsApp:
      <a href="https://wa.me/254721110572">
        +254 721 110 572
      </a>
    </p>

  </div>


  <!-- ===== ABOUT ===== -->
  <section class="section" id="about">

    <div class="container">

      <div class="section-label">
        Who We Are
      </div>

      <h2 class="section-title">
        About Husika Events
      </h2>


      <div class="about-grid">

        <div class="about-main">

          <p class="about-intro">
            Husika Events was founded on a simple yet powerful belief: every child deserves to feel safe, every community member deserves dignity, and every voice deserves to be heard.
          </p>

          <p>
            Rooted in Kenyan communities, Husika brings together volunteers, professionals, and families to create programmes that educate, protect, and uplift. From child welfare campaigns to community outreach, we are on the ground where it matters most.
          </p>


          <div class="pillars">

            <div class="pillar pillar--green">

              <h4>Our Mission</h4>

              <p>
                To empower communities to protect children, prevent abuse, and foster environments where every individual can thrive.
              </p>

            </div>


            <div class="pillar pillar--teal">

              <h4>Our Vision</h4>

              <p>
                A Kenya where no child suffers in silence and every community has the tools to stand up for the vulnerable.
              </p>

            </div>

          </div>

        </div>


        <div class="about-sidebar">

          <div class="info-card">

            <h3>Our Focus Areas</h3>

            <ul class="focus-list">

              <li>
                <span class="focus-dot dot--red"></span>
                Child Sexual Abuse Prevention
              </li>

              <li>
                <span class="focus-dot dot--green"></span>
                Anti-Bullying Campaigns
              </li>

              <li>
                <span class="focus-dot dot--teal"></span>
                Child Trafficking Awareness
              </li>

              <li>
                <span class="focus-dot dot--gold"></span>
                Drug Abuse Prevention
              </li>

              <li>
                <span class="focus-dot dot--green"></span>
                Community Education
              </li>

            </ul>

          </div>


          <div class="info-card info-card--green">

            <h3>Management</h3>

            <p>
              Our leadership team comprises passionate advocates, social workers, and community leaders dedicated to lasting impact.
            </p>

            <a href="staff.html" class="link-arrow">
              Meet the team →
            </a>

          </div>

        </div>

      </div>


      <!-- Departments -->

      <div class="section-label" style="margin-top: 3rem;">
        Our Groups & Departments
      </div>


      <div class="dept-grid">

        <div class="dept-card">
          <div class="dept-icon">👶</div>
          <h4>Children's Group</h4>
          <p>
            Ages 5–12. Play-based learning, safety education, and creative arts.
          </p>
        </div>


        <div class="dept-card">
          <div class="dept-icon">🧑</div>
          <h4>Youth Department</h4>
          <p>
            Ages 13–25. Leadership, mentorship, and life skills development.
          </p>
        </div>


        <div class="dept-card">
          <div class="dept-icon">👨‍👩‍👧</div>
          <h4>Families & Parents</h4>
          <p>
            Parenting support, family counselling, and community bonding.
          </p>
        </div>


        <div class="dept-card">
          <div class="dept-icon">📚</div>
          <h4>Education Wing</h4>
          <p>
            School partnerships, tutoring programmes, and scholarship support.
          </p>
        </div>


        <div class="dept-card">
          <div class="dept-icon">🏥</div>
          <h4>Welfare & Health</h4>
          <p>
            Medical outreach, mental health support, and nutritional aid.
          </p>
        </div>


        <div class="dept-card">
          <div class="dept-icon">⚖️</div>
          <h4>Legal & Advocacy</h4>
          <p>
            Rights education, legal referrals, and policy advocacy.
          </p>
        </div>

      </div>

    </div>

  </section>


  <!-- ===== ACTIVITIES ===== -->
  <section class="section section--alt" id="activities">

    <div class="container">

      <div class="section-label">
        What We Do
      </div>

      <h2 class="section-title">
        Activities & Programmes
      </h2>

      <p class="section-sub">
        Browse our upcoming and ongoing activities. Filter by group or schedule.
      </p>


      <div class="filter-bar">

        <button class="filter-btn active" data-filter="all">
          All
        </button>

        <button class="filter-btn" data-filter="children">
          Children
        </button>

        <button class="filter-btn" data-filter="youth">
          Youth
        </button>

        <button class="filter-btn" data-filter="family">
          Families
        </button>

        <button class="filter-btn" data-filter="school">
          School Term
        </button>

        <button class="filter-btn" data-filter="holiday">
          Holiday
        </button>

      </div>


      <div class="activities-grid">

        <div class="activity-card" data-category="children school">

          <div class="activity-tag tag--green">
            Children · School Term
          </div>

          <h4>Safe Touch Workshop</h4>

          <p>
            Age-appropriate education on body safety, boundaries, and speaking up about uncomfortable situations.
          </p>

          <div class="activity-meta">

            <span>📅 Every 2nd Saturday</span>

            <span>📍 Nairobi Centre</span>

          </div>

        </div>


        <div class="activity-card" data-category="youth school">

          <div class="activity-tag tag--teal">
            Youth · School Term
          </div>

          <h4>Anti-Drug Campaign</h4>

          <p>
            Peer-to-peer sessions on the impact of substance abuse and building resilience among teenagers.
          </p>

          <div class="activity-meta">

            <span>📅 Bi-weekly Fridays</span>

            <span>📍 Various Schools</span>

          </div>

        </div>


        <div class="activity-card" data-category="family holiday">

          <div class="activity-tag tag--gold">
            Families · Holiday
          </div>

          <h4>Family Safety Day</h4>

          <p>
            A fun-filled community gathering focused on child protection awareness and family bonding activities.
          </p>

          <div class="activity-meta">

            <span>📅 School Holidays</span>

            <span>📍 Community Grounds</span>

          </div>

        </div>


        <div class="activity-card" data-category="youth holiday">

          <div class="activity-tag tag--teal">
            Youth · Holiday
          </div>

          <h4>Leadership Camp</h4>

          <p>
            Residential camp for teens focusing on leadership, self-awareness, and community responsibility.
          </p>

          <div class="activity-meta">

            <span>📅 August Holiday</span>

            <span>📍 TBA</span>

          </div>

        </div>


        <div class="activity-card" data-category="children holiday">

          <div class="activity-tag tag--green">
            Children · Holiday
          </div>

          <h4>Creative Arts Festival</h4>

          <p>
            Drawing, drama, and storytelling for children to express themselves and process their experiences safely.
          </p>

          <div class="activity-meta">

            <span>📅 April Holiday</span>

            <span>📍 Husika HQ</span>

          </div>

        </div>


        <div class="activity-card activity-card--admin" data-category="all">

          <div class="activity-tag tag--red">
            Admin Only
          </div>

          <h4>+ Add New Activity</h4>

          <p>
            Administrators can add, edit, and categorise activities directly from the dashboard.
          </p>

          <a href="admin.php" class="btn btn--outline btn--sm">
            Go to Dashboard
          </a>

        </div>

      </div>

    </div>

  </section>


  <!-- ===== REPORT ===== -->
  <section class="section section--report" id="report">

    <div class="container container--narrow">

      <div class="section-label label--light">
        Confidential
      </div>

      <h2 class="section-title title--light">
        Report an Incident
      </h2>

      <p class="section-sub sub--light">
        Your report is confidential. We take every report seriously and will connect you to the right support.
      </p>


      <!-- SUCCESS / ERROR MESSAGE -->

      <?php if ($success && isset($_GET['success'])): ?>

        <div class="form-success">
          <?= htmlspecialchars($success) ?>
        </div>

      <?php endif; ?>


      <?php if ($error && isset($_GET['error'])): ?>

        <div class="form-error">
          <?= htmlspecialchars($error) ?>
        </div>

      <?php endif; ?>


      <div class="report-cards">

        <div class="report-type">
          <span class="report-icon">🚨</span>
          <span>Child Sexual Abuse</span>
        </div>

        <div class="report-type">
          <span class="report-icon">👊</span>
          <span>Bullying</span>
        </div>

        <div class="report-type">
          <span class="report-icon">⛓️</span>
          <span>Child Trafficking</span>
        </div>

        <div class="report-type">
          <span class="report-icon">💊</span>
          <span>Drug Abuse</span>
        </div>

        <div class="report-type">
          <span class="report-icon">📋</span>
          <span>Other Concern</span>
        </div>

      </div>


      <form
        class="report-form"
        id="report-form"
        method="POST"
        action="index.php#report"
      >

        <input type="hidden" name="action" value="report">


        <div class="form-row">

          <div class="form-group">

            <label for="report-type">
              Type of Incident *
            </label>

            <select
              id="report-type"
              name="incident_type"
              required
            >

              <option value="">
                — Select —
              </option>

              <option>
                Child Sexual Abuse
              </option>

              <option>
                Bullying
              </option>

              <option>
                Child Trafficking
              </option>

              <option>
                Drug Abuse
              </option>

              <option>
                Other
              </option>

            </select>

          </div>


          <div class="form-group">

            <label for="report-location">
              Location / Area
            </label>

            <input
              type="text"
              id="report-location"
              name="location"
              placeholder="e.g. Mathare, Nairobi"
            />

          </div>

        </div>


        <div class="form-group">

          <label for="report-description">
            What happened? *
          </label>

          <textarea
            id="report-description"
            name="description"
            rows="5"
            placeholder="Describe what you witnessed or experienced. You do not need to share your name."
            required
          ></textarea>

        </div>


        <div class="form-row">

          <div class="form-group">

            <label for="reporter-name">
              Your Name (optional)
            </label>

            <input
              type="text"
              id="reporter-name"
              name="reporter_name"
              placeholder="Anonymous if preferred"
            />

          </div>


          <div class="form-group">

            <label for="reporter-contact">
              Phone / WhatsApp (optional)
            </label>

            <input
              type="tel"
              id="reporter-contact"
              name="phone"
              placeholder="+254 ..."
            />

          </div>

        </div>


        <div class="form-check">

          <input
            type="checkbox"
            id="report-consent"
            required
          />

          <label for="report-consent">
            I understand this report will be reviewed by Husika Events and may be escalated to relevant authorities.
          </label>

        </div>


        <button
          type="submit"
          class="btn btn--primary btn--full"
        >
          Submit Report Securely
        </button>


        <p class="form-note">

          Prefer WhatsApp?

          Text us directly:

          <a href="https://wa.me/254721110572">
            +254 721 110 572
          </a>

        </p>

      </form>

    </div>

  </section>


  <!-- ===== GALLERY ===== -->
  <section class="section" id="gallery">

    <div class="container">

      <div class="section-label">
        In Pictures
      </div>

      <h2 class="section-title">
        Pictorials
      </h2>

      <p class="section-sub">
        Moments from our programmes, events, and community impact.
      </p>


      <div class="gallery-grid">

        <div class="gallery-item gallery-item--wide">

          <div class="gallery-placeholder">

            <span>📸</span>

            <p>
              Community Safety Day 2024
            </p>

          </div>

        </div>


        <div class="gallery-item">

          <div class="gallery-placeholder">

            <span>📸</span>

            <p>
              Youth Leadership Camp
            </p>

          </div>

        </div>


        <div class="gallery-item">

          <div class="gallery-placeholder">

            <span>📸</span>

            <p>
              Children's Workshop
            </p>

          </div>

        </div>


        <div class="gallery-item">

          <div class="gallery-placeholder">

            <span>📸</span>

            <p>
              School Outreach
            </p>

          </div>

        </div>


        <div class="gallery-item">

          <div class="gallery-placeholder">

            <span>📸</span>

            <p>
              Awareness Campaign
            </p>

          </div>

        </div>

      </div>


      <div class="gallery-cta">

        <a href="#login" class="btn btn--outline">
          Members: Upload Photos
        </a>

      </div>

    </div>

  </section>


  <!-- ===== CONTACT ===== -->
  <section class="section section--alt" id="contact">

    <div class="container">

      <div class="section-label">
        Get In Touch
      </div>

      <h2 class="section-title">
        Contact & Information
      </h2>


      <div class="contact-grid">

        <div class="contact-card contact-card--primary">

          <div class="contact-card-icon">
            📱
          </div>

          <h4>
            WhatsApp / Text
          </h4>

          <p>
            Reach us any time for reports, inquiries, or membership.
          </p>

          <a
            href="https://wa.me/254721110572"
            class="contact-value"
          >
            +254 721 110 572
          </a>

        </div>


        <div class="contact-card">

          <div class="contact-card-icon">
            📧
          </div>

          <h4>
            Email Us
          </h4>

          <p>
            For formal correspondence and partnership enquiries.
          </p>

          <a
            href="mailto:info@husikaevents.org"
            class="contact-value"
          >
            info@husikaevents.org
          </a>

        </div>


        <div class="contact-card">

          <div class="contact-card-icon">
            📍
          </div>

          <h4>
            Visit Us
          </h4>

          <p>
            Based in Nairobi, serving communities across Kenya.
          </p>

          <span class="contact-value">
            Nairobi, Kenya
          </span>

        </div>


        <div class="contact-card">

          <div class="contact-card-icon">
            🌐
          </div>

          <h4>
            Social Media
          </h4>

          <p>
            Follow us for updates, campaigns, and community stories.
          </p>

          <span class="contact-value">
            @HusikaEvents
          </span>

        </div>

      </div>

    </div>

  </section>


  <!-- ===== LOGIN ===== -->
  <section class="section" id="login">

    <div class="container container--narrow">

      <div class="section-label">
        Members Portal
      </div>

      <h2 class="section-title">
        Login or Join Husika
      </h2>


      <!-- SUCCESS MESSAGE -->

      <?php if ($success): ?>

        <div class="form-success" id="success-message">
          <?= htmlspecialchars($success) ?>
        </div>

      <?php endif; ?>


      <!-- ERROR MESSAGE -->

      <?php if ($error): ?>

        <div class="form-error" id="error-message">
          <?= htmlspecialchars($error) ?>
        </div>

      <?php endif; ?>


      <div class="auth-tabs">

        <button
          type="button"
          class="auth-tab active"
          id="tab-login"
          onclick="showTab('login')"
        >
          Existing Member
        </button>


        <button
          type="button"
          class="auth-tab"
          id="tab-register"
          onclick="showTab('register')"
        >
          New Member
        </button>

      </div>


      <!-- LOGIN FORM -->

      <form
        class="auth-form"
        id="form-login"
        method="POST"
        action="index.php#login"
      >

        <input
          type="hidden"
          name="action"
          value="login"
        >


        <div class="form-group">

          <label for="login-email">
            Email Address
          </label>

          <input
            type="email"
            id="login-email"
            name="email"
            placeholder="you@email.com"
            required
          />

        </div>


        <div class="form-group">

          <label for="login-pass">
            Password
          </label>

          <input
            type="password"
            id="login-pass"
            name="password"
            placeholder="••••••••"
            required
          />

        </div>


        <button
          type="submit"
          class="btn btn--primary btn--full"
        >
          Log In
        </button>


        <p class="form-note">
          <a href="forgot-password.php">
            Forgot password?
          </a>
        </p>

      </form>


      <!-- REGISTER FORM -->

      <form
        class="auth-form hidden"
        id="form-register"
        method="POST"
        action="index.php#login"
      >

        <input
          type="hidden"
          name="action"
          value="register"
        >


        <div class="form-row">

          <div class="form-group">

            <label for="reg-fname">
              First Name
            </label>

            <input
              type="text"
              id="reg-fname"
              name="first_name"
              placeholder="Jane"
              required
            />

          </div>


          <div class="form-group">

            <label for="reg-lname">
              Last Name
            </label>

            <input
              type="text"
              id="reg-lname"
              name="last_name"
              placeholder="Wanjiku"
              required
            />

          </div>

        </div>


        <div class="form-group">

          <label for="reg-email">
            Email Address
          </label>

          <input
            type="email"
            id="reg-email"
            name="email"
            placeholder="you@email.com"
            required
          />

        </div>


        <div class="form-group">

          <label for="reg-phone">
            WhatsApp Number
          </label>

          <input
            type="tel"
            id="reg-phone"
            name="phone"
            placeholder="+254 ..."
          />

        </div>


        <div class="form-group">

          <label for="reg-group">
            Which group are you joining?
          </label>

          <select
            id="reg-group"
            name="group_name"
          >

            <option value="">
              — Select —
            </option>

            <option>
              Children's Group (5–12)
            </option>

            <option>
              Youth Department (13–25)
            </option>

            <option>
              Families & Parents
            </option>

            <option>
              Volunteer / Supporter
            </option>

          </select>

        </div>


        <div class="form-group">

          <label for="reg-pass">
            Create Password
          </label>

          <input
            type="password"
            id="reg-pass"
            name="password"
            placeholder="••••••••"
            minlength="6"
            required
          />

        </div>


        <button
          type="submit"
          class="btn btn--primary btn--full"
        >
          Create Account
        </button>

      </form>

    </div>

  </section>


  <!-- ===== FOOTER ===== -->
  <footer class="footer">

    <div class="container">

      <div class="footer-top">

        <div class="footer-brand">

          <span class="brand-husika">
            Husika
          </span>

          <span class="brand-events">
            EVENTS
          </span>

          <p>
            Give Hope · Give Love · Give Back
          </p>

        </div>


        <div class="footer-links">

          <h5>
            Quick Links
          </h5>

          <a href="#about">
            About Us
          </a>

          <a href="#activities">
            Activities
          </a>

          <a href="#report">
            Report
          </a>

          <a href="#gallery">
            Gallery
          </a>

          <a href="#contact">
            Contact
          </a>

        </div>


        <div class="footer-links">

          <h5>
            Support
          </h5>

          <a href="#login">
            Member Login
          </a>

          <a href="#report">
            Report Incident
          </a>

          <a href="https://wa.me/254721110572">
            WhatsApp Us
          </a>

        </div>


        <div class="footer-emergency">

          <h5>
            Emergency?
          </h5>

          <p>
            Text or WhatsApp us immediately:
          </p>

          <a
            href="https://wa.me/254721110572"
            class="emergency-num"
          >
            +254 721 110 572
          </a>

        </div>

      </div>


      <div class="footer-bottom">

        <p>
          © 2025 Husika Events. All rights reserved [MonroeLeslie].
        </p>

        <p>
          You are not alone — help is always available.
        </p>

      </div>

    </div>

  </footer>


  <script>

    // Navbar scroll effect
    window.addEventListener('scroll', () => {

      document
        .getElementById('navbar')
        .classList
        .toggle('scrolled', window.scrollY > 50);

    });


    // Hamburger menu
    document
      .getElementById('hamburger')
      .addEventListener('click', () => {

        document
          .getElementById('nav-links')
          .classList
          .toggle('open');

      });


    // Active nav on scroll
    const sections =
      document.querySelectorAll('section[id]');

    window.addEventListener('scroll', () => {

      const scrollY =
        window.scrollY + 100;

      sections.forEach(sec => {

        if (
          scrollY >= sec.offsetTop &&
          scrollY < sec.offsetTop + sec.offsetHeight
        ) {

          document
            .querySelectorAll('.nav-link')
            .forEach(l =>
              l.classList.remove('active')
            );

          const link =
            document.querySelector(
              `.nav-link[href="#${sec.id}"]`
            );

          if (link) {
            link.classList.add('active');
          }

        }

      });

    });

    // Activity filter
    document
      .querySelectorAll('.filter-btn')
      .forEach(btn => {

        btn.addEventListener('click', () => {

          document
            .querySelectorAll('.filter-btn')
            .forEach(b =>
              b.classList.remove('active')
            );

          btn.classList.add('active');

          const filter =
            btn.dataset.filter;

          document
            .querySelectorAll('.activity-card')
            .forEach(card => {

              const cat =
                card.dataset.category || '';

              card.style.display =
                (
                  filter === 'all' ||
                  cat.includes(filter)
                )
                  ? ''
                  : 'none';

            });

        });

      });


    // Auth tabs
    function showTab(tab) {

      document
        .getElementById('form-login')
        .classList
        .toggle(
          'hidden',
          tab !== 'login'
        );

      document
        .getElementById('form-register')
        .classList
        .toggle(
          'hidden',
          tab !== 'register'
        );

      document
        .getElementById('tab-login')
        .classList
        .toggle(
          'active',
          tab === 'login'
        );

      document
        .getElementById('tab-register')
        .classList
        .toggle(
          'active',
          tab === 'register'
        );

    }


    // Report form
    document
      .getElementById('report-form')
      .addEventListener('submit', e => {

        const consent =
          document.getElementById('report-consent');

        if (!consent.checked) {

          e.preventDefault();

          alert(
            'Please confirm that you understand how your report will be handled.'
          );

        }

      });


    /*
    |--------------------------------------------------------------------------
    | KEEP LOGIN SECTION OPEN AFTER REGISTRATION / LOGIN ERROR
    |--------------------------------------------------------------------------
    */

    <?php if ($success || $error): ?>

      document
        .getElementById('login')
        .scrollIntoView({
          behavior: 'smooth'
        });

    <?php endif; ?>


  </script>

</body>
</html>