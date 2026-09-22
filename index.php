<?php
declare(strict_types=1);

$projectRoot = __DIR__;
$seedUploadsDir = $projectRoot . DIRECTORY_SEPARATOR . 'uploads';
$configuredStorage = getenv('GVP_PORTAL_STORAGE');
$storageDir = $configuredStorage !== false && trim($configuredStorage) !== ''
    ? $configuredStorage
    : sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'gvp_portal_' . substr(md5($projectRoot), 0, 8);
$runtimeUploadsDir = $storageDir . DIRECTORY_SEPARATOR . 'uploads';
$sessionDir = $storageDir . DIRECTORY_SEPARATOR . 'sessions';
$dbPath = $storageDir . DIRECTORY_SEPARATOR . 'gvp_portal.sqlite';
$categories = ['Syllabus', 'Academic Calendar', 'Question Paper', 'Materials'];

if (!is_dir($storageDir)) {
    @mkdir($storageDir, 0777, true);
}

if (!is_dir($sessionDir)) {
    @mkdir($sessionDir, 0777, true);
}

if (!is_dir($runtimeUploadsDir)) {
    @mkdir($runtimeUploadsDir, 0777, true);
}

session_save_path($sessionDir);
session_start();

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function redirectTo(string $url): void
{
    header('Location: ' . $url);
    exit;
}

function tableHasColumn(PDO $conn, string $table, string $column): bool
{
    $stmt = $conn->query("PRAGMA table_info($table)");

    foreach ($stmt->fetchAll() as $row) {
        if (($row['name'] ?? '') === $column) {
            return true;
        }
    }

    return false;
}

function detectCategory(string $filename): string
{
    $name = strtoupper($filename);

    if (str_contains($name, 'SYLLABUS')) {
        return 'Syllabus';
    }

    if (str_contains($name, 'CALENDAR')) {
        return 'Academic Calendar';
    }

    if (str_contains($name, 'QUESTION')) {
        return 'Question Paper';
    }

    return 'Materials';
}

function cleanedTitle(string $filename): string
{
    $base = pathinfo($filename, PATHINFO_FILENAME);
    $cleaned = preg_replace('/^\d+_/', '', $base);
    $cleaned = str_replace(['_', '-'], ' ', (string) $cleaned);
    return trim((string) preg_replace('/\s+/', ' ', $cleaned));
}

function csrfToken(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_token'];
}

function verifyCsrf(): void
{
    $token = $_POST['csrf_token'] ?? '';

    if (!is_string($token) || !hash_equals($_SESSION['csrf_token'] ?? '', $token)) {
        http_response_code(403);
        exit('Invalid request token.');
    }
}

function currentUser(): ?array
{
    if (!isset($_SESSION['user_id'])) {
        return null;
    }

    return [
        'id' => (int) $_SESSION['user_id'],
        'username' => (string) ($_SESSION['username'] ?? ''),
        'full_name' => (string) ($_SESSION['full_name'] ?? 'Portal User'),
        'role' => (string) ($_SESSION['role'] ?? 'faculty'),
    ];
}

function requireLogin(): array
{
    $user = currentUser();

    if ($user === null) {
        redirectTo('index.php?view=login');
    }

    return $user;
}

function requireAdmin(): array
{
    $user = requireLogin();

    if ($user['role'] !== 'admin') {
        redirectTo('index.php?view=dashboard&status=not_allowed');
    }

    return $user;
}

function statusMessage(string $status): ?array
{
    $messages = [
        'login_failed' => ['error', 'Invalid username or password.'],
        'logged_out' => ['success', 'You have been logged out.'],
        'uploaded' => ['success', 'Resource uploaded successfully.'],
        'missing_fields' => ['error', 'Please fill in all required fields.'],
        'invalid_file' => ['error', 'That file type or category is not allowed.'],
        'upload_error' => ['error', 'Upload failed. Please try again.'],
        'deleted' => ['success', 'Resource deleted successfully.'],
        'faculty_created' => ['success', 'Faculty login created successfully.'],
        'faculty_deleted' => ['success', 'Faculty login removed successfully.'],
        'faculty_exists' => ['error', 'That username already exists.'],
        'invalid_id' => ['error', 'Invalid record selected.'],
        'not_allowed' => ['error', 'Only the main admin can manage faculty credentials.'],
    ];

    return $messages[$status] ?? null;
}

try {
    $conn = new PDO('sqlite:' . $dbPath);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $conn->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

    $conn->exec(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'faculty')),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )"
    );

    $conn->exec(
        "CREATE TABLE IF NOT EXISTS resources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            filename TEXT NOT NULL,
            original_name TEXT,
            category TEXT NOT NULL,
            uploaded_by INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )"
    );

    $conn->exec(
        "CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL DEFAULT 'Portal User',
            role TEXT NOT NULL DEFAULT 'faculty',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )"
    );

    $conn->exec(
        "CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            filename TEXT NOT NULL,
            original_name TEXT,
            category TEXT NOT NULL,
            uploaded_by INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )"
    );

    foreach (['full_name' => "TEXT NOT NULL DEFAULT 'Portal User'", 'role' => "TEXT NOT NULL DEFAULT 'faculty'"] as $column => $definition) {
        if (!tableHasColumn($conn, 'admins', $column)) {
            $conn->exec("ALTER TABLE admins ADD COLUMN $column $definition");
        }
    }

    if (!tableHasColumn($conn, 'uploads', 'uploaded_by')) {
        $conn->exec("ALTER TABLE uploads ADD COLUMN uploaded_by INTEGER");
    }

    $legacyUsers = $conn->query('SELECT id, username, password, full_name, role, created_at FROM admins')->fetchAll();
    foreach ($legacyUsers as $legacyUser) {
        $stmt = $conn->prepare(
            "INSERT OR IGNORE INTO users (id, username, password, full_name, role, created_at)
             VALUES (:id, :username, :password, :full_name, :role, :created_at)"
        );
        $stmt->execute([
            ':id' => $legacyUser['id'],
            ':username' => $legacyUser['username'],
            ':password' => $legacyUser['password'],
            ':full_name' => $legacyUser['full_name'] ?: $legacyUser['username'],
            ':role' => in_array($legacyUser['role'], ['admin', 'faculty'], true) ? $legacyUser['role'] : 'faculty',
            ':created_at' => $legacyUser['created_at'],
        ]);
    }

    $legacyResources = $conn->query('SELECT id, title, description, filename, original_name, category, uploaded_by, created_at FROM uploads')->fetchAll();
    foreach ($legacyResources as $legacyResource) {
        $stmt = $conn->prepare(
            "INSERT OR IGNORE INTO resources (id, title, description, filename, original_name, category, uploaded_by, created_at)
             VALUES (:id, :title, :description, :filename, :original_name, :category, :uploaded_by, :created_at)"
        );
        $stmt->execute([
            ':id' => $legacyResource['id'],
            ':title' => $legacyResource['title'],
            ':description' => $legacyResource['description'],
            ':filename' => $legacyResource['filename'],
            ':original_name' => $legacyResource['original_name'],
            ':category' => $legacyResource['category'],
            ':uploaded_by' => $legacyResource['uploaded_by'],
            ':created_at' => $legacyResource['created_at'],
        ]);
    }

    if ((int) $conn->query("SELECT COUNT(*) FROM users WHERE role = 'admin'")->fetchColumn() === 0) {
        $stmt = $conn->prepare(
            "INSERT OR IGNORE INTO users (username, password, full_name, role)
             VALUES ('admin', :password, 'Portal Administrator', 'admin')"
        );
        $stmt->execute([':password' => password_hash('admin123', PASSWORD_DEFAULT)]);
    }

    if ((int) $conn->query('SELECT COUNT(*) FROM resources')->fetchColumn() === 0 && is_dir($seedUploadsDir)) {
        $stmt = $conn->prepare(
            "INSERT INTO resources (title, description, filename, original_name, category)
             VALUES (:title, :description, :filename, :original_name, :category)"
        );

        foreach (glob($seedUploadsDir . DIRECTORY_SEPARATOR . '*') as $filePath) {
            if (!is_file($filePath)) {
                continue;
            }

            $originalName = basename($filePath);
            $title = cleanedTitle($originalName);
            $stmt->execute([
                ':title' => $title,
                ':description' => $title,
                ':filename' => $filePath,
                ':original_name' => $originalName,
                ':category' => detectCategory($originalName),
            ]);
        }
    }
} catch (Throwable $exception) {
    http_response_code(500);
    exit('Application startup failed: ' . e($exception->getMessage()));
}

$action = $_POST['action'] ?? $_GET['action'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCsrf();

    if ($action === 'login') {
        $username = trim((string) ($_POST['username'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');
        $stmt = $conn->prepare('SELECT id, username, password, full_name, role FROM users WHERE username = :username LIMIT 1');
        $stmt->execute([':username' => $username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            session_regenerate_id(true);
            $_SESSION['user_id'] = (int) $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['full_name'] = $user['full_name'];
            $_SESSION['role'] = $user['role'];
            redirectTo('index.php?view=dashboard');
        }

        redirectTo('index.php?view=login&status=login_failed');
    }

    if ($action === 'upload_resource') {
        $user = requireLogin();
        $title = trim((string) ($_POST['title'] ?? ''));
        $description = trim((string) ($_POST['description'] ?? ''));
        $category = trim((string) ($_POST['category'] ?? ''));
        $file = $_FILES['file'] ?? null;
        $allowedExtensions = ['pdf', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'jpg', 'jpeg', 'png'];

        if ($title === '' || $description === '' || $category === '' || !is_array($file)) {
            redirectTo('index.php?view=dashboard&status=missing_fields');
        }

        $originalName = basename((string) ($file['name'] ?? ''));
        $safeName = preg_replace('/[^A-Za-z0-9._-]/', '_', $originalName);
        $extension = strtolower(pathinfo((string) $safeName, PATHINFO_EXTENSION));

        if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
            redirectTo('index.php?view=dashboard&status=upload_error');
        }

        if (!in_array($extension, $allowedExtensions, true) || !in_array($category, $categories, true)) {
            redirectTo('index.php?view=dashboard&status=invalid_file');
        }

        $targetFile = $runtimeUploadsDir . DIRECTORY_SEPARATOR . time() . '_' . $safeName;

        if (!move_uploaded_file((string) $file['tmp_name'], $targetFile)) {
            redirectTo('index.php?view=dashboard&status=upload_error');
        }

        $stmt = $conn->prepare(
            "INSERT INTO resources (title, description, filename, original_name, category, uploaded_by)
             VALUES (:title, :description, :filename, :original_name, :category, :uploaded_by)"
        );
        $stmt->execute([
            ':title' => $title,
            ':description' => $description,
            ':filename' => $targetFile,
            ':original_name' => $originalName,
            ':category' => $category,
            ':uploaded_by' => $user['id'],
        ]);

        redirectTo('index.php?view=manage&status=uploaded');
    }

    if ($action === 'delete_resource') {
        $user = requireLogin();
        $id = (int) ($_POST['id'] ?? 0);

        if ($id <= 0) {
            redirectTo('index.php?view=manage&status=invalid_id');
        }

        $stmt = $conn->prepare('SELECT filename, uploaded_by FROM resources WHERE id = :id');
        $stmt->execute([':id' => $id]);
        $resource = $stmt->fetch();

        if (!$resource || ($user['role'] !== 'admin' && (int) $resource['uploaded_by'] !== $user['id'])) {
            redirectTo('index.php?view=manage&status=not_allowed');
        }

        $filePath = (string) $resource['filename'];
        $realFile = realpath($filePath);
        $realRuntimeUploads = realpath($runtimeUploadsDir);

        if ($realFile && $realRuntimeUploads && str_starts_with($realFile, $realRuntimeUploads) && is_file($realFile)) {
            unlink($realFile);
        }

        $stmt = $conn->prepare('DELETE FROM resources WHERE id = :id');
        $stmt->execute([':id' => $id]);
        redirectTo('index.php?view=manage&status=deleted');
    }

    if ($action === 'create_faculty') {
        requireAdmin();
        $fullName = trim((string) ($_POST['full_name'] ?? ''));
        $username = trim((string) ($_POST['username'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');

        if ($fullName === '' || $username === '' || $password === '') {
            redirectTo('index.php?view=faculty&status=missing_fields');
        }

        $stmt = $conn->prepare('SELECT id FROM users WHERE username = :username LIMIT 1');
        $stmt->execute([':username' => $username]);

        if ($stmt->fetch()) {
            redirectTo('index.php?view=faculty&status=faculty_exists');
        }

        $stmt = $conn->prepare(
            "INSERT INTO users (username, password, full_name, role)
             VALUES (:username, :password, :full_name, 'faculty')"
        );
        $stmt->execute([
            ':username' => $username,
            ':password' => password_hash($password, PASSWORD_DEFAULT),
            ':full_name' => $fullName,
        ]);

        redirectTo('index.php?view=faculty&status=faculty_created');
    }

    if ($action === 'delete_faculty') {
        requireAdmin();
        $id = (int) ($_POST['id'] ?? 0);

        if ($id <= 0) {
            redirectTo('index.php?view=faculty&status=invalid_id');
        }

        $stmt = $conn->prepare("DELETE FROM users WHERE id = :id AND role = 'faculty'");
        $stmt->execute([':id' => $id]);
        redirectTo('index.php?view=faculty&status=faculty_deleted');
    }
}

if ($action === 'logout') {
    session_unset();
    session_destroy();
    redirectTo('index.php?view=login&status=logged_out');
}

if ($action === 'download') {
    $id = (int) ($_GET['id'] ?? 0);
    $stmt = $conn->prepare('SELECT filename, original_name FROM resources WHERE id = :id');
    $stmt->execute([':id' => $id]);
    $resource = $stmt->fetch();

    if (!$resource || empty($resource['filename']) || !is_file($resource['filename'])) {
        http_response_code(404);
        exit('File not found.');
    }

    $filePath = (string) $resource['filename'];
    $downloadName = str_replace(['"', "\r", "\n"], '', (string) ($resource['original_name'] ?: basename($filePath)));
    $mimeType = mime_content_type($filePath) ?: 'application/octet-stream';

    header('Content-Type: ' . $mimeType);
    header('Content-Length: ' . filesize($filePath));
    header('Content-Disposition: inline; filename="' . $downloadName . '"');
    readfile($filePath);
    exit;
}

$view = (string) ($_GET['view'] ?? 'home');
$status = (string) ($_GET['status'] ?? '');
$user = currentUser();
$statusMessage = statusMessage($status);

$q = trim((string) ($_GET['q'] ?? ''));
$category = trim((string) ($_GET['category'] ?? ''));
$resourceSql = "SELECT resources.id, resources.title, resources.description, resources.category, resources.uploaded_by,
                       resources.original_name, resources.created_at, users.full_name AS uploader_name
                FROM resources
                LEFT JOIN users ON users.id = resources.uploaded_by
                WHERE (resources.title LIKE :search OR resources.description LIKE :search OR resources.original_name LIKE :search)";
$resourceParams = [':search' => '%' . $q . '%'];

if ($category !== '' && in_array($category, $categories, true)) {
    $resourceSql .= ' AND resources.category = :category';
    $resourceParams[':category'] = $category;
}

$resourceSql .= ' ORDER BY resources.created_at DESC, resources.id DESC';
$stmt = $conn->prepare($resourceSql);
$stmt->execute($resourceParams);
$resources = $stmt->fetchAll();

$facultyRows = [];
if ($user && $user['role'] === 'admin') {
    $facultyRows = $conn->query(
        "SELECT id, username, full_name, created_at
         FROM users
         WHERE role = 'faculty'
         ORDER BY created_at DESC, id DESC"
    )->fetchAll();
}

$resourceCount = (int) $conn->query('SELECT COUNT(*) FROM resources')->fetchColumn();
$facultyCount = (int) $conn->query("SELECT COUNT(*) FROM users WHERE role = 'faculty'")->fetchColumn();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GVPW Student Resource Portal</title>
  <link rel="stylesheet" href="css/style.css">
</head>
<body>
  <header class="site-header">
    <div class="brand">
      <div class="brand-badge">GVPW</div>
      <div>
        <h1>GVPW Resource Portal</h1>
        <p>Unified student, faculty, and admin resource management system.</p>
      </div>
    </div>
    <nav class="top-nav">
      <a class="top-link" href="index.php">Student Portal</a>
      <?php if ($user): ?>
        <a class="top-link" href="index.php?view=dashboard">Dashboard</a>
        <a class="top-link danger" href="index.php?action=logout">Logout</a>
      <?php else: ?>
        <a class="top-link" href="index.php?view=login">Login</a>
      <?php endif; ?>
    </nav>
  </header>

  <?php if ($statusMessage): ?>
    <div class="global-status">
      <div class="status <?= e($statusMessage[0]) ?>"><?= e($statusMessage[1]) ?></div>
    </div>
  <?php endif; ?>

  <?php if ($view === 'login'): ?>
    <main class="auth-page">
      <section class="login-box">
        <h1>Portal Login</h1>
        <p>Admin and faculty users sign in here to upload and manage academic resources.</p>
        <form action="index.php" method="POST">
          <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
          <input type="hidden" name="action" value="login">
          <input type="text" name="username" placeholder="Username" required>
          <input type="password" name="password" placeholder="Password" required>
          <button type="submit">Login</button>
        </form>
        <p class="demo-note">Main admin: admin / admin123</p>
      </section>
    </main>
  <?php elseif (in_array($view, ['dashboard', 'manage', 'faculty'], true)): ?>
    <?php $user = requireLogin(); ?>
    <div class="layout">
      <aside class="sidebar">
        <h2><?= e($user['role'] === 'admin' ? 'Admin' : 'Faculty') ?></h2>
        <p class="sidebar-user"><?= e($user['full_name']) ?></p>
        <ul>
          <li><a href="index.php?view=dashboard">Upload Files</a></li>
          <li><a href="index.php?view=manage">Manage Files</a></li>
          <?php if ($user['role'] === 'admin'): ?>
            <li><a href="index.php?view=faculty">Faculty Logins</a></li>
          <?php endif; ?>
          <li><a href="index.php">Student Portal</a></li>
        </ul>
      </aside>
      <main class="content">
        <?php if ($view === 'dashboard'): ?>
          <section class="intro-panel compact-panel">
            <div>
              <span class="eyebrow"><?= e(strtoupper($user['role'])) ?> WORKSPACE</span>
              <h2>Upload academic resources.</h2>
              <p>Resources appear immediately in the student search portal after upload.</p>
            </div>
            <div class="stats-grid">
              <div><strong><?= $resourceCount ?></strong><span>Files</span></div>
              <div><strong><?= $facultyCount ?></strong><span>Faculty</span></div>
              <div><strong>4</strong><span>Categories</span></div>
            </div>
          </section>
          <section class="card">
            <h2>Upload Resource</h2>
            <form action="index.php" method="POST" enctype="multipart/form-data" class="upload-form">
              <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
              <input type="hidden" name="action" value="upload_resource">
              <label>
                Title
                <input type="text" name="title" placeholder="Example: CSE I Year Syllabus" required>
              </label>
              <label>
                Description
                <textarea name="description" placeholder="Short summary for students" required></textarea>
              </label>
              <label>
                Category
                <select name="category" required>
                  <option value="">Select Category</option>
                  <?php foreach ($categories as $item): ?>
                    <option value="<?= e($item) ?>"><?= e($item) ?></option>
                  <?php endforeach; ?>
                </select>
              </label>
              <label>
                Resource File
                <input type="file" name="file" accept=".pdf,.doc,.docx,.ppt,.pptx,.xls,.xlsx,.jpg,.jpeg,.png" required>
              </label>
              <button type="submit">Upload File</button>
            </form>
          </section>
        <?php elseif ($view === 'manage'): ?>
          <section class="card">
            <div class="section-heading">
              <div>
                <h2>Manage Files</h2>
                <p>Admins can manage every file. Faculty can remove their own uploads.</p>
              </div>
            </div>
            <?php if (count($resources) === 0): ?>
              <p>No files found.</p>
            <?php else: ?>
              <div class="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Title</th>
                      <th>Category</th>
                      <th>Uploaded By</th>
                      <th>Uploaded</th>
                      <th>Open</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    <?php foreach ($resources as $resource): ?>
                      <?php $canDelete = $user['role'] === 'admin' || (int) $resource['uploaded_by'] === $user['id']; ?>
                      <tr>
                        <td><?= e($resource['title']) ?></td>
                        <td><span class="pill"><?= e($resource['category']) ?></span></td>
                        <td><?= e($resource['uploader_name'] ?: 'Seed Data') ?></td>
                        <td><?= e(date('d M Y', strtotime($resource['created_at']))) ?></td>
                        <td><a href="index.php?action=download&id=<?= (int) $resource['id'] ?>" target="_blank">Open</a></td>
                        <td class="action-cell">
                          <?php if ($canDelete): ?>
                            <form action="index.php" method="POST" onsubmit="return confirm('Delete this file?');">
                              <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
                              <input type="hidden" name="action" value="delete_resource">
                              <input type="hidden" name="id" value="<?= (int) $resource['id'] ?>">
                              <button type="submit" class="danger-btn">Delete</button>
                            </form>
                          <?php else: ?>
                            <span class="muted">View only</span>
                          <?php endif; ?>
                        </td>
                      </tr>
                    <?php endforeach; ?>
                  </tbody>
                </table>
              </div>
            <?php endif; ?>
          </section>
        <?php elseif ($view === 'faculty'): ?>
          <?php requireAdmin(); ?>
          <section class="card">
            <h2>Create Faculty Login</h2>
            <form action="index.php" method="POST" class="upload-form">
              <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
              <input type="hidden" name="action" value="create_faculty">
              <label>
                Faculty Name
                <input type="text" name="full_name" placeholder="Example: Dr. Priya Sharma" required>
              </label>
              <label>
                Username
                <input type="text" name="username" placeholder="Example: priya.cse" required>
              </label>
              <label>
                Temporary Password
                <input type="password" name="password" placeholder="Create a login password" required>
              </label>
              <button type="submit">Create Faculty Login</button>
            </form>
          </section>
          <section class="card">
            <h2>Faculty Accounts</h2>
            <?php if (count($facultyRows) === 0): ?>
              <p>No faculty logins have been created yet.</p>
            <?php else: ?>
              <div class="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Faculty Name</th>
                      <th>Username</th>
                      <th>Created</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    <?php foreach ($facultyRows as $faculty): ?>
                      <tr>
                        <td><?= e($faculty['full_name']) ?></td>
                        <td><?= e($faculty['username']) ?></td>
                        <td><?= e(date('d M Y', strtotime($faculty['created_at']))) ?></td>
                        <td class="action-cell">
                          <form action="index.php" method="POST" onsubmit="return confirm('Remove this faculty login?');">
                            <input type="hidden" name="csrf_token" value="<?= e(csrfToken()) ?>">
                            <input type="hidden" name="action" value="delete_faculty">
                            <input type="hidden" name="id" value="<?= (int) $faculty['id'] ?>">
                            <button type="submit" class="danger-btn">Remove</button>
                          </form>
                        </td>
                      </tr>
                    <?php endforeach; ?>
                  </tbody>
                </table>
              </div>
            <?php endif; ?>
          </section>
        <?php endif; ?>
      </main>
    </div>
  <?php else: ?>
    <div class="layout">
      <aside class="sidebar">
        <h2>Browse</h2>
        <ul>
          <li><a href="index.php">Home</a></li>
          <?php foreach ($categories as $item): ?>
            <li><a href="index.php?category=<?= urlencode($item) ?>"><?= e($item) ?></a></li>
          <?php endforeach; ?>
        </ul>
      </aside>
      <main class="content">
        <section class="intro-panel">
          <div>
            <span class="eyebrow">Full Stack Portal</span>
            <h2>Search verified academic resources in one place.</h2>
            <p>Students search files, faculty upload resources, and admins manage faculty credentials in one unified app.</p>
          </div>
          <div class="stats-grid">
            <div><strong><?= $resourceCount ?></strong><span>Resources</span></div>
            <div><strong><?= $facultyCount ?></strong><span>Faculty</span></div>
            <div><strong>SQLite</strong><span>Backend</span></div>
          </div>
        </section>

        <section class="card">
          <div class="section-heading">
            <div>
              <h2>Search Resources</h2>
              <p><?= count($resources) ?> file<?= count($resources) === 1 ? '' : 's' ?> found.</p>
            </div>
          </div>
          <form action="index.php" method="GET" class="search-form">
            <input type="text" name="q" value="<?= e($q) ?>" placeholder="Search by title, subject, or file name">
            <select name="category">
              <option value="">All Categories</option>
              <?php foreach ($categories as $item): ?>
                <option value="<?= e($item) ?>" <?= $category === $item ? 'selected' : '' ?>><?= e($item) ?></option>
              <?php endforeach; ?>
            </select>
            <button type="submit">Search</button>
          </form>
        </section>

        <section class="category-grid">
          <?php foreach ($categories as $item): ?>
            <a href="index.php?category=<?= urlencode($item) ?>" class="category-card">
              <span><?= e($item) ?></span>
              <strong>Browse <?= e(strtolower($item)) ?> resources</strong>
            </a>
          <?php endforeach; ?>
        </section>

        <section class="card">
          <h2>Available Resources</h2>
          <?php if (count($resources) === 0): ?>
            <p>No files found for your search.</p>
          <?php else: ?>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Title</th>
                    <th>Category</th>
                    <th>Description</th>
                    <th>Uploaded</th>
                    <th>File</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($resources as $resource): ?>
                    <tr>
                      <td><?= e($resource['title']) ?></td>
                      <td><span class="pill"><?= e($resource['category']) ?></span></td>
                      <td><?= e($resource['description']) ?></td>
                      <td><?= e(date('d M Y', strtotime($resource['created_at']))) ?></td>
                      <td><a href="index.php?action=download&id=<?= (int) $resource['id'] ?>" target="_blank">Open</a></td>
                    </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>
          <?php endif; ?>
        </section>
      </main>
    </div>
  <?php endif; ?>
</body>
</html>
