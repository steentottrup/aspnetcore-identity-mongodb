using System;

namespace CreativeMinds.Identity.MongoDBStores {

	public class MongoDBIdentityStoreOptions {
		public String ConnectionString { get; set; }
		public String UserCollectionName { get; set; } = "users";
		public String RoleCollectionName { get; set; } = "roles";
	}
}
