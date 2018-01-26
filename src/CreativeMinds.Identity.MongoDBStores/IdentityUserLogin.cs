using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;

namespace CreativeMinds.Identity.MongoDBStores
{

	public class IdentityUserLogin : IdentityUserLogin<ObjectId> {

		public IdentityUserLogin() { }

		public IdentityUserLogin(String loginProvider, String providerKey, String providerDisplayName) {
			this.LoginProvider = loginProvider;
			this.ProviderDisplayName = providerDisplayName;
			this.ProviderKey = providerKey;
		}

		[BsonElement(FieldNames.LoginProvider)]
		public override String LoginProvider { get; set; }
		[BsonElement(FieldNames.ProviderDisplayName)]
		public override String ProviderDisplayName { get; set; }
		[BsonElement(FieldNames.ProviderKey)]
		public override String ProviderKey { get; set; }

		public static class FieldNames {
			public const String LoginProvider = "lip";
			public const String ProviderDisplayName = "n";
			public const String ProviderKey = "k";
		}
	}
}