using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Security.Claims;

namespace CreativeMinds.Identity.MongoDBStores
{

	public class IdentityUserClaim : IdentityUserClaim<ObjectId> {

		public IdentityUserClaim() { }

		public IdentityUserClaim(Claim claim) {
			this.ClaimType = claim.Type;
			this.ClaimValue = claim.Value;
		}

		[BsonElement(FieldNames.Type)]
		public override String ClaimType { get; set; }
		[BsonElement(FieldNames.Value)]
		public override String ClaimValue { get; set; }

		public Claim ToSecurityClaim() {
			return new Claim(this.ClaimType, this.ClaimValue);
		}

		public static class FieldNames {
			public const String Type = "t";
			public const String Value = "v";
		}
	}
}