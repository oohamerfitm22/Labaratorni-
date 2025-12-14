using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

public class UserService
{
    private List<User> users = new List<User>();

    public void Register()
    {
        Console.Write("Enter username: ");
        string username = Console.ReadLine() ?? string.Empty;

        Console.Write("Enter password: ");
        string password = Console.ReadLine() ?? string.Empty;

        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            Console.WriteLine("Username and password cannot be empty.");
            return;
        }

        string hashed = HashPassword(password);
        users.Add(new User { Username = username, Password = hashed });

        Console.WriteLine("User registered successfully!");
    }

    public void Login()
    {
        Console.Write("Enter username: ");
        string username = Console.ReadLine() ?? string.Empty;

        Console.Write("Enter password: ");
        string password = Console.ReadLine() ?? string.Empty;

        string hashed = HashPassword(password);
        User user = users.Find(u => u.Username == username && u.Password == hashed);

        if (user != null)
        {
            Console.WriteLine("Login successful!");
        }
        else
        {
            Console.WriteLine("Login failed!");
        }
    }

    private string HashPassword(string password)
    {
        using SHA256 sha = SHA256.Create();
        byte[] bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(password));
        return Convert.ToBase64String(bytes);
    }

    public List<User> GetUsers()
    {
        return users;
    }
}
