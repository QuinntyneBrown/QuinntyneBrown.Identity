namespace QuinntyneBrown.Identity
{
    public interface IPasswordHasher
    {
        string HashPassword(Byte[] salt, string password);
    }
}
