//package UserAuthenticationSystem;
//version 2
import java.io.*;
import java.util.*;
import java.security.*;
import java.util.regex.Pattern;

public class UserAuthenticationSystem {
    private static final String USER_FILE = "users.txt";
    private static final String SALT_FILE = "salts.txt";
    private static final int MIN_PASSWORD_LENGTH = 8;
    private static final int MAX_USERNAME_LENGTH = 30;
    private static final int MAX_PASSWORD_LENGTH = 128;
    
    // Password strength patterns
    private static final Pattern LOWERCASE_PATTERN = Pattern.compile(".*[a-z].*");
    private static final Pattern UPPERCASE_PATTERN = Pattern.compile(".*[A-Z].*");
    private static final Pattern DIGIT_PATTERN = Pattern.compile(".*[0-9].*");
    private static final Pattern SPECIAL_CHAR_PATTERN = Pattern.compile(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*");
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_]{3,30}$");
    
    private Map<String, String> users; // username -> hashed password
    private Map<String, String> salts; // username -> salt
    private SecureRandom random;

    public UserAuthenticationSystem() {
        users = new HashMap<>();
        salts = new HashMap<>();
        random = new SecureRandom();
        loadUsers();
        loadSalts();
    }

    private void loadUsers() {
        File userFile = new File(USER_FILE);
        if (!userFile.exists()) {
            System.out.println("User file not found. Starting with empty user database.");
            return;
        }
        
        try (BufferedReader reader = new BufferedReader(new FileReader(USER_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2 && !parts[0].trim().isEmpty() && !parts[1].trim().isEmpty()) {
                    users.put(parts[0], parts[1]);
                }
            }
            System.out.println("Loaded " + users.size() + " users from database.");
        } catch (IOException e) {
            System.err.println("Error loading users: " + e.getMessage());
            System.err.println("Starting with empty user database.");
        } catch (SecurityException e) {
            System.err.println("Permission denied reading user file: " + e.getMessage());
            System.exit(1);
        }
    }

    private void loadSalts() {
        File saltFile = new File(SALT_FILE);
        if (!saltFile.exists()) {
            return;
        }
        
        try (BufferedReader reader = new BufferedReader(new FileReader(SALT_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2 && !parts[0].trim().isEmpty() && !parts[1].trim().isEmpty()) {
                    salts.put(parts[0], parts[1]);
                }
            }
        } catch (IOException e) {
            System.err.println("Error loading salts: " + e.getMessage());
        }
    }

    private void saveUsers() throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(USER_FILE))) {
            for (Map.Entry<String, String> entry : users.entrySet()) {
                writer.write(entry.getKey() + ":" + entry.getValue());
                writer.newLine();
            }
        } catch (SecurityException e) {
            throw new IOException("Permission denied writing to user file", e);
        }
    }

    private void saveSalts() throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(SALT_FILE))) {
            for (Map.Entry<String, String> entry : salts.entrySet()) {
                writer.write(entry.getKey() + ":" + entry.getValue());
                writer.newLine();
            }
        } catch (SecurityException e) {
            throw new IOException("Permission denied writing to salt file", e);
        }
    }

    private String generateSalt() {
        byte[] saltBytes = new byte[32];
        random.nextBytes(saltBytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : saltBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private String hashPasswordWithSalt(String password, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            String saltedPassword = password + salt;
            byte[] hashedBytes = md.digest(saltedPassword.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : hashedBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }

    public ValidationResult validateUsername(String username) {
        if (username == null || username.trim().isEmpty()) {
            return new ValidationResult(false, "Username cannot be empty.");
        }
        
        username = username.trim();
        
        if (username.length() < 3) {
            return new ValidationResult(false, "Username must be at least 3 characters long.");
        }
        
        if (username.length() > MAX_USERNAME_LENGTH) {
            return new ValidationResult(false, "Username cannot exceed " + MAX_USERNAME_LENGTH + " characters.");
        }
        
        if (!USERNAME_PATTERN.matcher(username).matches()) {
            return new ValidationResult(false, "Username can only contain letters, numbers, and underscores.");
        }
        
        return new ValidationResult(true, "Valid username.");
    }

    public ValidationResult validatePassword(String password) {
        if (password == null || password.isEmpty()) {
            return new ValidationResult(false, "Password cannot be empty.");
        }
        
        if (password.length() < MIN_PASSWORD_LENGTH) {
            return new ValidationResult(false, "Password must be at least " + MIN_PASSWORD_LENGTH + " characters long.");
        }
        
        if (password.length() > MAX_PASSWORD_LENGTH) {
            return new ValidationResult(false, "Password cannot exceed " + MAX_PASSWORD_LENGTH + " characters.");
        }
        
        List<String> missingRequirements = new ArrayList<>();
        
        if (!LOWERCASE_PATTERN.matcher(password).matches()) {
            missingRequirements.add("at least one lowercase letter");
        }
        if (!UPPERCASE_PATTERN.matcher(password).matches()) {
            missingRequirements.add("at least one uppercase letter");
        }
        if (!DIGIT_PATTERN.matcher(password).matches()) {
            missingRequirements.add("at least one digit");
        }
        if (!SPECIAL_CHAR_PATTERN.matcher(password).matches()) {
            missingRequirements.add("at least one special character (!@#$%^&*()_+-=[]{}|;':\"\\,.<>/?)");
        }
        
        if (!missingRequirements.isEmpty()) {
            return new ValidationResult(false, "Password must contain: " + String.join(", ", missingRequirements));
        }
        
        return new ValidationResult(true, "Strong password.");
    }

    public AuthResult registerUser(String username, String password) {
        try {
            ValidationResult usernameValidation = validateUsername(username);
            if (!usernameValidation.isValid()) {
                return new AuthResult(false, usernameValidation.getMessage());
            }
            
            ValidationResult passwordValidation = validatePassword(password);
            if (!passwordValidation.isValid()) {
                return new AuthResult(false, passwordValidation.getMessage());
            }
            
            username = username.trim();
            
            if (users.containsKey(username)) {
                return new AuthResult(false, "Username '" + username + "' already exists. Please choose a different username.");
            }
            
            String salt = generateSalt();
            String hashedPassword = hashPasswordWithSalt(password, salt);
            
            users.put(username, hashedPassword);
            salts.put(username, salt);
            
            saveUsers();
            saveSalts();
            
            return new AuthResult(true, "User '" + username + "' registered successfully.");
            
        } catch (IOException e) {
            return new AuthResult(false, "Registration failed due to file system error: " + e.getMessage());
        } catch (Exception e) {
            return new AuthResult(false, "Registration failed due to unexpected error: " + e.getMessage());
        }
    }

    public AuthResult authenticateUser(String username, String password) {
        try {
            if (username == null || username.trim().isEmpty()) {
                return new AuthResult(false, "Username cannot be empty.");
            }
            
            if (password == null || password.isEmpty()) {
                return new AuthResult(false, "Password cannot be empty.");
            }
            
            username = username.trim();
            
            String storedHash = users.get(username);
            String salt = salts.get(username);
            
            if (storedHash == null || salt == null) {
                return new AuthResult(false, "Invalid username or password.");
            }
            
            String inputHash = hashPasswordWithSalt(password, salt);
            
            if (storedHash.equals(inputHash)) {
                return new AuthResult(true, "Login successful. Welcome, " + username + "!");
            } else {
                return new AuthResult(false, "Invalid username or password.");
            }
            
        } catch (Exception e) {
            return new AuthResult(false, "Authentication failed due to unexpected error: " + e.getMessage());
        }
    }

    public AuthResult resetPassword(String username, String newPassword) {
        try {
            ValidationResult usernameValidation = validateUsername(username);
            if (!usernameValidation.isValid()) {
                return new AuthResult(false, usernameValidation.getMessage());
            }
            
            ValidationResult passwordValidation = validatePassword(newPassword);
            if (!passwordValidation.isValid()) {
                return new AuthResult(false, passwordValidation.getMessage());
            }
            
            username = username.trim();
            
            if (!users.containsKey(username)) {
                return new AuthResult(false, "User '" + username + "' not found.");
            }
            
            String newSalt = generateSalt();
            String hashedPassword = hashPasswordWithSalt(newPassword, newSalt);
            
            users.put(username, hashedPassword);
            salts.put(username, newSalt);
            
            saveUsers();
            saveSalts();
            
            return new AuthResult(true, "Password reset successfully for user '" + username + "'.");
            
        } catch (IOException e) {
            return new AuthResult(false, "Password reset failed due to file system error: " + e.getMessage());
        } catch (Exception e) {
            return new AuthResult(false, "Password reset failed due to unexpected error: " + e.getMessage());
        }
    }

    private String getSecureInput(Scanner scanner, String prompt, boolean isPassword) {
        System.out.print(prompt);
        if (isPassword) {
            // Note: In a real application, you'd use Console.readPassword() for hidden input
            System.out.print("(Input will be visible - in production, use Console.readPassword()): ");
        }
        
        try {
            String input = scanner.nextLine();
            return input;
        } catch (Exception e) {
            System.err.println("Error reading input: " + e.getMessage());
            return "";
        }
    }

    private int getMenuChoice(Scanner scanner) {
        try {
            System.out.print("Choose an option (1-4): ");
            String input = scanner.nextLine().trim();
            
            if (input.isEmpty()) {
                return -1;
            }
            
            int choice = Integer.parseInt(input);
            if (choice < 1 || choice > 4) {
                return -1;
            }
            return choice;
            
        } catch (NumberFormatException e) {
            return -1;
        } catch (Exception e) {
            System.err.println("Error reading input: " + e.getMessage());
            return -1;
        }
    }

    public static void main(String[] args) {
        System.out.println("=== Enhanced User Authentication System ===");
        System.out.println("Features: Secure password hashing with salt, input validation, strong password requirements");
        System.out.println();
        
        UserAuthenticationSystem authSystem = new UserAuthenticationSystem();
        Scanner scanner = new Scanner(System.in);
        
        while (true) {
            System.out.println("\n" + "=".repeat(50));
            System.out.println("1. Register New User");
            System.out.println("2. Login");
            System.out.println("3. Reset Password");
            System.out.println("4. Exit");
            System.out.println("=".repeat(50));
            
            int choice = authSystem.getMenuChoice(scanner);
            
            if (choice == -1) {
                System.out.println("Invalid option. Please enter a number between 1 and 4.");
                continue;
            }
            
            switch (choice) {
                case 1:
                    System.out.println("\n--- User Registration ---");
                    System.out.println("Username requirements: 3-30 characters, letters, numbers, and underscores only");
                    System.out.println("Password requirements: 8+ characters with uppercase, lowercase, digit, and special character");
                    System.out.println();
                    
                    String regUsername = authSystem.getSecureInput(scanner, "Enter username: ", false);
                    String regPassword = authSystem.getSecureInput(scanner, "Enter password: ", true);
                    
                    AuthResult regResult = authSystem.registerUser(regUsername, regPassword);
                    System.out.println(regResult.isSuccess() ? "✓ " + regResult.getMessage() : "✗ " + regResult.getMessage());
                    break;
                    
                case 2:
                    System.out.println("\n--- User Login ---");
                    String loginUsername = authSystem.getSecureInput(scanner, "Enter username: ", false);
                    String loginPassword = authSystem.getSecureInput(scanner, "Enter password: ", true);
                    
                    AuthResult loginResult = authSystem.authenticateUser(loginUsername, loginPassword);
                    System.out.println(loginResult.isSuccess() ? "✓ " + loginResult.getMessage() : "✗ " + loginResult.getMessage());
                    break;
                    
                case 3:
                    System.out.println("\n--- Password Reset ---");
                    System.out.println("Password requirements: 8+ characters with uppercase, lowercase, digit, and special character");
                    System.out.println();
                    
                    String resetUsername = authSystem.getSecureInput(scanner, "Enter username: ", false);
                    String newPassword = authSystem.getSecureInput(scanner, "Enter new password: ", true);
                    
                    AuthResult resetResult = authSystem.resetPassword(resetUsername, newPassword);
                    System.out.println(resetResult.isSuccess() ? "✓ " + resetResult.getMessage() : "✗ " + resetResult.getMessage());
                    break;
                    
                case 4:
                    System.out.println("\nThank you for using Enhanced User Authentication System!");
                    scanner.close();
                    System.exit(0);
            }
        }
    }
    
    // Helper classes for better error handling and validation
    public static class ValidationResult {
        private final boolean valid;
        private final String message;
        
        public ValidationResult(boolean valid, String message) {
            this.valid = valid;
            this.message = message;
        }
        
        public boolean isValid() { return valid; }
        public String getMessage() { return message; }
    }
    
    public static class AuthResult {
        private final boolean success;
        private final String message;
        
        public AuthResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
        
        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
    }
}
