using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;

namespace CreativeMinds.Identity.MongoDBStores
{

	public class IdentityUserToken : IdentityUserToken<ObjectId> {
		[BsonElement(FieldNames.LoginProvider)]
		public override String LoginProvider { get; set; }
		[BsonElement(FieldNames.Name)]
		public override String Name { get; set; }
		[BsonElement(FieldNames.Value)]
		public override String Value { get; set; }

		public static class FieldNames {
			public const String LoginProvider = "lip";
			public const String Name = "n";
			public const String Value = "v";
		}
	}
}