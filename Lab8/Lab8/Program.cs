using System;

class Program
{
    static void Main()
    {
        UserService service = new UserService();

        while (true)
        {
            Console.WriteLine("1. Register");
            Console.WriteLine("2. Login");
            Console.WriteLine("3. Exit");
            Console.Write("Choice: ");
            string choice = Console.ReadLine() ?? string.Empty;

            switch (choice)
            {
                case "1":
                    service.Register();
                    break;
                case "2":
                    service.Login();
                    break;
                case "3":
                    return;
                default:
                    Console.WriteLine("Invalid choice!");
                    break;
            }

            Console.WriteLine("\n--- Current Users ---");
            foreach (var user in service.GetUsers())
            {
                Console.WriteLine($"Username: {user.Username}, Password: {user.Password}");
            }
            Console.WriteLine("----------------------\n");
        }
    }
}
