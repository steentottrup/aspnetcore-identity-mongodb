using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;

namespace CreativeMinds.Identity.MongoDBStores {

	public class IdentityRole {

		public IdentityRole() { }

		public IdentityRole(String roleName) : this() {
			this.Name = roleName;
		}

		public virtual ObjectId Id { get; set; }
		[BsonElement(FieldNames.Name)]
		public virtual String Name { get; set; }
		[BsonElement(FieldNames.NormalizedName)]
		public virtual String NormalizedName { get; set; }

		public static class FieldNames {
			public const String Id = "_id";
			public const String Name = "n";
			public const String NormalizedName = "nn";
		}
	}
}
