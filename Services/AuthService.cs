namespace ap_auth_server.Services
{
    public class AuthService
    {
        public async Task<bool> SignIn(string username, string password)
        {
            return true;
        }

        public async Task<bool> SignUp(string username, string password)
        {
            return true;
        }

        public static string HashPassword(string password)
        {
            return password;
        }

        public static string CreateNewPassword()
        {
            Random random = new Random(); //Instancia la función random
            string characters = "abcdefghijklmnopqrstuvwxyzABCEFGHIJKLMNOPQRSTUVWXYZ123456789*!.-";
            var newPassword = new char[15]; //Se inicia un arreglo de 15 posiciones
            for (int i = 0; i < newPassword.Length; i++)
            {
                newPassword[i] = characters[random.Next(characters.Length)];
            }
            var password = new string(newPassword);
            return password;
        }
    }
}
