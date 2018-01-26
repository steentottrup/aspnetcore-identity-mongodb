using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;

namespace CreativeMinds.Identity.MongoDBStores {

	public class MongoDBIdentityUser {

		public MongoDBIdentityUser() {
			this.Roles = new List<UserRole>();
			this.Logins = new List<IdentityUserLogin>();
			this.Claims = new List<IdentityUserClaim>();
			this.Tokens = new List<IdentityUserToken>();
		}

		[BsonElement(FieldNames.Id)]
		[BsonRepresentation(BsonType.ObjectId)]
		public virtual ObjectId Id { get; set; }
		[BsonElement(FieldNames.UserName)]
		public virtual String UserName { get; set; }
		[BsonElement(FieldNames.NormalizedUserName)]
		public virtual String NormalizedUserName { get; set; }
		[BsonElement(FieldNames.SecurityStamp)]
		public virtual String SecurityStamp { get; set; }
		[BsonElement(FieldNames.Email)]
		public virtual String Email { get; set; }
		[BsonElement(FieldNames.NormalizedEmail)]
		public virtual String NormalizedEmail { get; set; }
		[BsonElement(FieldNames.EmailConfirmed)]
		public virtual Boolean EmailConfirmed { get; set; }
		[BsonElement(FieldNames.PhoneNumber)]
		public virtual String PhoneNumber { get; set; }
		[BsonElement(FieldNames.PhoneNumberConfirmed)]
		public virtual Boolean PhoneNumberConfirmed { get; set; }
		[BsonElement(FieldNames.TwoFactorEnabled)]
		public virtual Boolean TwoFactorEnabled { get; set; }
		[BsonElement(FieldNames.LockoutEndDateUtc)]
		public virtual DateTime? LockoutEndDateUtc { get; set; }
		[BsonElement(FieldNames.LockoutEnabled)]
		public virtual Boolean LockoutEnabled { get; set; }
		[BsonElement(FieldNames.AccessFailedCount)]
		public virtual Int32 AccessFailedCount { get; set; }
		[BsonIgnoreIfNull]
		[BsonElement(FieldNames.Roles)]
		public virtual IEnumerable<UserRole> Roles { get; set; }
		[BsonIgnoreIfNull]
		[BsonElement(FieldNames.PasswordHash)]
		public virtual String PasswordHash { get; set; }
		[BsonIgnoreIfNull]
		[BsonElement(FieldNames.Logins)]
		public virtual IEnumerable<IdentityUserLogin> Logins { get; set; }
		[BsonIgnoreIfNull]
		[BsonElement(FieldNames.Claims)]
		public virtual IEnumerable<IdentityUserClaim> Claims { get; set; }
		[BsonIgnoreIfNull]
		[BsonElement(FieldNames.Tokens)]
		public virtual IEnumerable<IdentityUserToken> Tokens { get; set; }

		public static class FieldNames {
			public const String Id = "_id";
			public const String UserName = "un";
			public const String NormalizedUserName = "nun";
			public const String SecurityStamp = "ss";
			public const String Email = "em";
			public const String NormalizedEmail = "nem";
			public const String EmailConfirmed = "emc";
			public const String PhoneNumber = "pn";
			public const String PhoneNumberConfirmed = "pnc";
			public const String TwoFactorEnabled = "tfe";
			public const String LockoutEndDateUtc = "led";
			public const String LockoutEnabled = "le";
			public const String AccessFailedCount = "afc";
			public const String Roles = "rs";
			public const String PasswordHash = "ph";
			public const String Logins = "ls";
			public const String Claims = "cs";
			public const String Tokens = "ts";
		}
	}
}
