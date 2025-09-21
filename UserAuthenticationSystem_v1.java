package UserAuthenticationSystem;
//version 1
import java.io.*;
import java.util.*;
import java.security.*;

public class UserAuthenticationSystem {
    private static final String USER_FILE = "users.txt";
    private Map<String, String> users;

    public UserAuthenticationSystem() {
        users = new HashMap<>();
        loadUsers();
    }

    private void loadUsers() {
        try (BufferedReader reader = new BufferedReader(new FileReader(USER_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(":");
                if (parts.length == 2) {
                    users.put(parts[0], parts[1]);
                }
            }
        } catch (IOException e) {
            System.err.println("Error loading users: " + e.getMessage());
        }
    }

    private void saveUsers() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(USER_FILE))) {
            for (Map.Entry<String, String> entry : users.entrySet()) {
                writer.write(entry.getKey() + ":" + entry.getValue());
                writer.newLine();
            }
        } catch (IOException e) {
            System.err.println("Error saving users: " + e.getMessage());
        }
    }

    public boolean registerUser(String username, String password) {
        if (users.containsKey(username)) {
            return false;
        }
        users.put(username, hashPassword(password));
        saveUsers();
        return true;
    }

    public boolean authenticateUser(String username, String password) {
        String storedHash = users.get(username);
        return storedHash != null && storedHash.equals(hashPassword(password));
    }

    public boolean resetPassword(String username, String newPassword) {
        if (!users.containsKey(username)) {
            return false;
        }
        users.put(username, hashPassword(newPassword));
        saveUsers();
        return true;
    }

    private String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hashedBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }
    public static void main(String[] args) {
        UserAuthenticationSystem authSystem = new UserAuthenticationSystem();
        Scanner scanner = new Scanner(System.in);
        
        while (true) {
            System.out.println("\n1. Register\n2. Login\n3. Reset Password\n4. Exit");
            System.out.print("Choose an option: ");
            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume newline
            
            switch (choice) {
                case 1:
                    System.out.print("Enter username: ");
                    String regUsername = scanner.nextLine();
                    System.out.print("Enter password: ");
                    String regPassword = scanner.nextLine();
                    if (authSystem.registerUser(regUsername, regPassword)) {
                        System.out.println("User registered successfully.");
                    } else {
                        System.out.println("Username already exists.");
                    }
                    break;
                case 2:
                    System.out.print("Enter username: ");
                    String loginUsername = scanner.nextLine();
                    System.out.print("Enter password: ");
                    String loginPassword = scanner.nextLine();
                    if (authSystem.authenticateUser(loginUsername, loginPassword)) {
                        System.out.println("Login successful.");
                    } else {
                        System.out.println("Invalid username or password.");
                    }
                    break;
                case 3:
                    System.out.print("Enter username: ");
                    String resetUsername = scanner.nextLine();
                    System.out.print("Enter new password: ");
                    String newPassword = scanner.nextLine();
                    if (authSystem.resetPassword(resetUsername, newPassword)) {
                        System.out.println("Password reset successfully.");
                    } else {
                        System.out.println("User not found.");
                    }
                    break;
                case 4:
                    System.out.println("Exiting...");
                    scanner.close();
                    System.exit(0);
                default:
                    System.out.println("Invalid option. Please try again.");
            }
        }
    }
}

