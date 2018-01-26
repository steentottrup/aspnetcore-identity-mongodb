using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;

namespace CreativeMinds.Identity.MongoDBStores {

	public class UserRole : IdentityUserRole<ObjectId> {

		[BsonElement(FieldNames.Id)]
		public override ObjectId RoleId { get; set; }
		[BsonElement(FieldNames.Name)]
		public String Name { get; set; }

		public static class FieldNames {
			public const String Id = "i";
			public const String Name = "n";
		}
	}
}
