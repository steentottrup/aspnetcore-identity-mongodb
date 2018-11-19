using MongoDB.Driver;
using System;

namespace CreativeMinds.Identity.MongoDBStores.Tests {

	public class IdentityDatabase {
		private const String mongoUrl = "mongodb://localhost/test";
		private readonly IMongoCollection<MockRole> roles = null;
		private readonly IMongoCollection<MockUser> users = null;

		public IdentityDatabase() {
			MongoUrl url = new MongoUrl(mongoUrl);
			IMongoClient client = new MongoClient(url);
			IMongoDatabase database = client.GetDatabase(url.DatabaseName);
			this.roles = database.GetCollection<MockRole>($"role{DateTime.UtcNow.Ticks}");
			this.users = database.GetCollection<MockUser>($"user{DateTime.UtcNow.Ticks}");
		}

		public IMongoCollection<MockRole> RoleStore { get { return this.roles; } }
		public IMongoCollection<MockUser> UserStore { get { return this.users; } }
	}
}
