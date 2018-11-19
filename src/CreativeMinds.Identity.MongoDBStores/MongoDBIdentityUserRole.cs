using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;

namespace CreativeMinds.Identity.MongoDBStores {

	public class MongoDBIdentityUserRole {
		[BsonElement(FieldNames.Id)]
		public ObjectId RoleId { get; set; }
		[BsonElement(FieldNames.Name)]
		public String Name { get; set; }

		public static class FieldNames {
			public const String Id = "i";
			public const String Name = "n";
		}
	}
}
