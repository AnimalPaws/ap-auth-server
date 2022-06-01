namespace ap_auth_server.Autherization
{
    public class AllowAnonymousAttribute
    {
        [AttributeUsage(AttributeTargets.Method)]
        public class AllowAnonymousAttributeAttribute : Attribute { }
    }
}
