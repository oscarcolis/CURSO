<?php
header('Content-Type: application/json');
require_once 'conexion.php';

$data = json_decode(file_get_contents('php://input'), true);

$nombre = trim($data['nombre'] ?? '');
$email = trim($data['email'] ?? '');
$password = $data['password'] ?? '';

if (empty($nombre) || empty($email) || empty($password)) {
    echo json_encode(['error' => 'Nombre, email y contraseña son obligatorios']);
    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['error' => 'Email no válido']);
    exit;
}

if (strlen($password) < 6) {
    echo json_encode(['error' => 'La contraseña debe tener al menos 6 caracteres']);
    exit;
}

$hashedPassword = password_hash($password, PASSWORD_DEFAULT);

try {
    $stmt = $pdo->prepare("INSERT INTO usuarios (nombre, email, password) VALUES (?, ?, ?)");
    $stmt->execute([$nombre, $email, $hashedPassword]);
    echo json_encode(['success' => 'Registro exitoso. ¡Bienvenido!']);
} catch(PDOException $e) {
    if ($e->errorInfo[1] == 1062) {
        echo json_encode(['error' => 'Este email ya está registrado']);
    } else {
        echo json_encode(['error' => 'Error en la base de datos: ' . $e->getMessage()]);
    }
}
?>