using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

#nullable disable

namespace ap_auth_server.Models
{
    public partial class ap_dbContext : DbContext
    {
        public ap_dbContext()
        {
        }

        public ap_dbContext(DbContextOptions<ap_dbContext> options)
            : base(options)
        {
        }

        public virtual DbSet<Foundation> Foundations { get; set; }
        public virtual DbSet<FoundationProfile> FoundationProfiles { get; set; }
        public virtual DbSet<Token> Tokens { get; set; }
        public virtual DbSet<User> Users { get; set; }
        public virtual DbSet<UserProfile> UserProfiles { get; set; }
        public virtual DbSet<Veterinary> Veterinaries { get; set; }
        public virtual DbSet<VeterinaryProfile> VeterinaryProfiles { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
                //Conexión a la base de datos
                optionsBuilder.UseMySQL(connectionString:"APDatabase");
            }
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Foundation>(entity =>
            {
                entity.ToTable("foundation");

                entity.HasIndex(e => new { e.Email, e.PhoneNumber }, "email")
                    .IsUnique();

                entity.HasIndex(e => e.ProfileId, "profile_id")
                    .IsUnique();

                entity.Property(e => e.Id)
                    .HasColumnType("int(11)")
                    .HasColumnName("id");

                entity.Property(e => e.Address)
                    .IsRequired()
                    .HasMaxLength(150)
                    .HasColumnName("address");

                entity.Property(e => e.City)
                    .IsRequired()
                    .HasMaxLength(70)
                    .HasColumnName("city");

                entity.Property(e => e.CreatedAt)
                    .HasColumnName("created_at")
                    .HasDefaultValueSql("'NULL'");

                entity.Property(e => e.Department)
                    .IsRequired()
                    .HasMaxLength(60)
                    .HasColumnName("department");

                entity.Property(e => e.Email)
                    .IsRequired()
                    .HasMaxLength(100)
                    .HasColumnName("email");

                entity.Property(e => e.IsBlocked)
                    .HasColumnName("is_blocked")
                    .HasDefaultValueSql("'0'");

                entity.Property(e => e.IsRestricted)
                    .HasColumnName("is_restricted")
                    .HasDefaultValueSql("'0'");

                entity.Property(e => e.Name)
                    .IsRequired()
                    .HasMaxLength(120)
                    .HasColumnName("name");

                entity.Property(e => e.Password)
                    .IsRequired()
                    .HasMaxLength(100)
                    .HasColumnName("password");

                entity.Property(e => e.PhoneNumber)
                    .IsRequired()
                    .HasMaxLength(30)
                    .HasColumnName("phone_number")
                    .IsFixedLength(true);

                entity.Property(e => e.ProfileId)
                    .HasColumnType("int(11)")
                    .HasColumnName("profile_id")
                    .HasDefaultValueSql("'NULL'");

                entity.HasOne(d => d.Profile)
                    .WithOne(p => p.Foundation)
                    .HasForeignKey<Foundation>(d => d.ProfileId)
                    .HasConstraintName("foundation_has_profile");
            });

            modelBuilder.Entity<FoundationProfile>(entity =>
            {
                entity.ToTable("foundation_profile");

                entity.Property(e => e.Id)
                    .HasColumnType("int(11)")
                    .HasColumnName("id");

                entity.Property(e => e.About)
                    .HasMaxLength(200)
                    .HasColumnName("about")
                    .HasDefaultValueSql("'NULL'");

                entity.Property(e => e.NotificationId)
                    .HasColumnType("int(11)")
                    .HasColumnName("notification_id")
                    .HasDefaultValueSql("'NULL'");

                entity.Property(e => e.PetId)
                    .HasColumnType("int(11)")
                    .HasColumnName("pet_id")
                    .HasDefaultValueSql("'NULL'");

                entity.Property(e => e.Picture)
                    .HasColumnType("blob")
                    .HasColumnName("picture")
                    .HasDefaultValueSql("'NULL'");

                entity.Property(e => e.UpdatedAt)
                    .HasColumnName("updated_at")
                    .HasDefaultValueSql("'NULL'");
            });

            modelBuilder.Entity<Token>(entity =>
            {
                entity.ToTable("token");

                entity.Property(e => e.Id)
                    .HasColumnType("int(11)")
                    .HasColumnName("id");

                entity.Property(e => e.CreatedAt)
                    .HasColumnName("created_at")
                    .HasDefaultValueSql("'NULL'");

                entity.Property(e => e.IsRevoke)
                    .HasColumnName("is_revoke")
                    .HasDefaultValueSql("'NULL'");

                entity.Property(e => e.UpdatedAt)
                    .HasColumnName("updated_at")
                    .HasDefaultValueSql("'NULL'");
            });

            modelBuilder.Entity<User>(entity =>
            {
                entity.ToTable("user");

                entity.HasIndex(e => new { e.Email, e.PhoneNumber }, "email")
                    .IsUnique();

                entity.HasIndex(e => e.ProfileId, "profile_id")
                    .IsUnique();

                entity.Property(e => e.Id)
                    .HasColumnType("int(11)")
                    .HasColumnName("id");

                entity.Property(e => e.Birthdate)
                    .HasColumnType("date")
                    .HasColumnName("birthdate");

                entity.Property(e => e.City)
                    .IsRequired()
                    .HasMaxLength(70)
                    .HasColumnName("city");

                entity.Property(e => e.CreatedAt)
                    .HasColumnName("created_at")
                    .HasDefaultValueSql("'NULL'");

                entity.Property(e => e.Department)
                    .IsRequired()
                    .HasMaxLength(60)
                    .HasColumnName("department");

                entity.Property(e => e.Email)
                    .IsRequired()
                    .HasMaxLength(100)
                    .HasColumnName("email");

                entity.Property(e => e.FirstName)
                    .IsRequired()
                    .HasMaxLength(80)
                    .HasColumnName("first_name");

                entity.Property(e => e.IsBlocked)
                    .HasColumnName("is_blocked")
                    .HasDefaultValueSql("'0'");

                entity.Property(e => e.IsRestricted)
                    .HasColumnName("is_restricted")
                    .HasDefaultValueSql("'0'");

                entity.Property(e => e.LastName)
                    .IsRequired()
                    .HasMaxLength(80)
                    .HasColumnName("last_name");

                entity.Property(e => e.MiddleName)
                    .HasMaxLength(80)
                    .HasColumnName("middle_name")
                    .HasDefaultValueSql("'NULL'");

                entity.Property(e => e.Password)
                    .IsRequired()
                    .HasMaxLength(100)
                    .HasColumnName("password");

                entity.Property(e => e.PhoneNumber)
                    .HasMaxLength(30)
                    .HasColumnName("phone_number")
                    .HasDefaultValueSql("'NULL'")
                    .IsFixedLength(true);

                entity.Property(e => e.PhoneNumberVerified)
                    .HasColumnName("phone_number_verified")
                    .HasDefaultValueSql("'0'");

                entity.Property(e => e.ProfileId)
                    .HasColumnType("int(11)")
                    .HasColumnName("profile_id")
                    .HasDefaultValueSql("'NULL'");

                entity.Property(e => e.Sex)
                    .IsRequired()
                    .HasColumnType("enum('M','F','O')")
                    .HasColumnName("sex");

                entity.Property(e => e.Surname)
                    .IsRequired()
                    .HasMaxLength(80)
                    .HasColumnName("surname");

                entity.HasOne(d => d.Profile)
                    .WithOne(p => p.User)
                    .HasForeignKey<User>(d => d.ProfileId)
                    .HasConstraintName("user_has_profile");
            });

            modelBuilder.Entity<UserProfile>(entity =>
            {
                entity.ToTable("user_profile");

                entity.HasIndex(e => e.Username, "username")
                    .IsUnique();

                entity.Property(e => e.Id)
                    .HasColumnType("int(11)")
                    .HasColumnName("id");

                entity.Property(e => e.Biography)
                    .HasMaxLength(150)
                    .HasColumnName("biography")
                    .HasDefaultValueSql("'NULL'");

                entity.Property(e => e.EmailVerified)
                    .HasColumnName("email_verified")
                    .HasDefaultValueSql("'0'");

                entity.Property(e => e.NotificationId)
                    .HasColumnType("int(11)")
                    .HasColumnName("notification_id")
                    .HasDefaultValueSql("'NULL'");

                entity.Property(e => e.PetId)
                    .HasColumnType("int(11)")
                    .HasColumnName("pet_id")
                    .HasDefaultValueSql("'NULL'");

                entity.Property(e => e.Picture)
                    .HasColumnType("blob")
                    .HasColumnName("picture")
                    .HasDefaultValueSql("'NULL'");

                entity.Property(e => e.UpdatedAt)
                    .HasColumnName("updated_at")
                    .HasDefaultValueSql("'NULL'");

                entity.Property(e => e.Username)
                    .IsRequired()
                    .HasMaxLength(25)
                    .HasColumnName("username");
            });

            modelBuilder.Entity<Veterinary>(entity =>
            {
                entity.ToTable("veterinary");

                entity.HasIndex(e => new { e.Email, e.PhoneNumber }, "email")
                    .IsUnique();

                entity.HasIndex(e => e.ProfileId, "profile_id")
                    .IsUnique();

                entity.Property(e => e.Id)
                    .HasColumnType("int(11)")
                    .HasColumnName("id");

                entity.Property(e => e.Address)
                    .IsRequired()
                    .HasMaxLength(150)
                    .HasColumnName("address");

                entity.Property(e => e.City)
                    .IsRequired()
                    .HasMaxLength(70)
                    .HasColumnName("city");

                entity.Property(e => e.CreatedAt)
                    .HasColumnName("created_at")
                    .HasDefaultValueSql("'NULL'");

                entity.Property(e => e.Department)
                    .IsRequired()
                    .HasMaxLength(60)
                    .HasColumnName("department");

                entity.Property(e => e.Email)
                    .IsRequired()
                    .HasMaxLength(100)
                    .HasColumnName("email");

                entity.Property(e => e.IsBlocked)
                    .HasColumnName("is_blocked")
                    .HasDefaultValueSql("'0'");

                entity.Property(e => e.IsRestricted)
                    .HasColumnName("is_restricted")
                    .HasDefaultValueSql("'0'");

                entity.Property(e => e.Name)
                    .IsRequired()
                    .HasMaxLength(120)
                    .HasColumnName("name");

                entity.Property(e => e.Password)
                    .IsRequired()
                    .HasMaxLength(100)
                    .HasColumnName("password");

                entity.Property(e => e.PhoneNumber)
                    .IsRequired()
                    .HasMaxLength(30)
                    .HasColumnName("phone_number")
                    .IsFixedLength(true);

                entity.Property(e => e.ProfileId)
                    .HasColumnType("int(11)")
                    .HasColumnName("profile_id")
                    .HasDefaultValueSql("'NULL'");

                entity.HasOne(d => d.Profile)
                    .WithOne(p => p.Veterinary)
                    .HasForeignKey<Veterinary>(d => d.ProfileId)
                    .HasConstraintName("veterinary_has_profile");
            });

            modelBuilder.Entity<VeterinaryProfile>(entity =>
            {
                entity.ToTable("veterinary_profile");

                entity.Property(e => e.Id)
                    .HasColumnType("int(11)")
                    .HasColumnName("id");

                entity.Property(e => e.About)
                    .HasMaxLength(200)
                    .HasColumnName("about")
                    .HasDefaultValueSql("'NULL'");

                entity.Property(e => e.NotificationId)
                    .HasColumnType("int(11)")
                    .HasColumnName("notification_id")
                    .HasDefaultValueSql("'NULL'");

                entity.Property(e => e.PetId)
                    .HasColumnType("int(11)")
                    .HasColumnName("pet_id")
                    .HasDefaultValueSql("'NULL'");

                entity.Property(e => e.Picture)
                    .HasColumnType("blob")
                    .HasColumnName("picture")
                    .HasDefaultValueSql("'NULL'");

                entity.Property(e => e.UpdatedAt)
                    .HasColumnName("updated_at")
                    .HasDefaultValueSql("'NULL'");
            });

            OnModelCreatingPartial(modelBuilder);
        }

        partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
    }
}
