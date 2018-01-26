using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;

namespace CreativeMinds.Identity.MongoDBStores {

	public class MongoDBIdentityRole {

		public MongoDBIdentityRole() {
			this.Claims = new List<IdentityRoleClaim>();
		}

		public MongoDBIdentityRole(String roleName) : this() {
			this.Name = roleName;
		}

		[BsonElement(FieldNames.Id)]
		[BsonRepresentation(BsonType.ObjectId)]
		public virtual ObjectId Id { get; set; }
		[BsonElement(FieldNames.Name)]
		public virtual String Name { get; set; }
		[BsonElement(FieldNames.NormalizedName)]
		public virtual String NormalizedName { get; set; }
		[BsonIgnoreIfNull]
		[BsonElement(FieldNames.Claims)]
		public virtual IEnumerable<IdentityRoleClaim> Claims { get; set; }

		public static class FieldNames {
			public const String Id = "_id";
			public const String Name = "n";
			public const String NormalizedName = "nn";
			public const String Claims = "cs";
		}
	}
}
