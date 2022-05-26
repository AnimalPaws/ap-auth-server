using System;
using System.Collections.Generic;

#nullable disable

namespace ap_auth_server.Models
{
    public partial class Veterinary
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string PhoneNumber { get; set; }
        public string Department { get; set; }
        public string City { get; set; }
        public string Address { get; set; }
        public bool? IsBlocked { get; set; }
        public bool? IsRestricted { get; set; }
        public DateTime? CreatedAt { get; set; }
        public int? ProfileId { get; set; }

        public virtual VeterinaryProfile Profile { get; set; }
    }
}
