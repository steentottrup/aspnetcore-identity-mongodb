using MongoDB.Bson;
using MongoDB.Driver;
using System;

namespace CreativeMinds.Identity.MongoDBStores.Tests {

	public static class TestInit {

		static TestInit() {
		}

		private static Tuple<RoleStore<MockRole, ObjectId, MockUserRole, MockRoleClaim>, UserStore<MockUser, MockRole, MockUserToken>> GetStoresPrivate() {
			IdentityDatabase db = new IdentityDatabase();
			return new Tuple<RoleStore<MockRole, ObjectId, MockUserRole, MockRoleClaim>, UserStore<MockUser, MockRole, MockUserToken>>(
				new RoleStore<MockRole, ObjectId, MockUserRole, MockRoleClaim>(db.RoleStore),
				new UserStore<MockUser, MockRole, MockUserToken>(db.UserStore, db.RoleStore)
			);
		}

		private static RoleStore<MockRole, ObjectId, MockUserRole, MockRoleClaim> GetRoleStorePrivate() {
			IdentityDatabase db = new IdentityDatabase();
			return new RoleStore<MockRole, ObjectId, MockUserRole, MockRoleClaim>(db.RoleStore);
		}

		private static UserStore<MockUser, MockRole, MockUserToken> GetUserStorePrivate() {
			IdentityDatabase db = new IdentityDatabase();
			return new UserStore<MockUser, MockRole, MockUserToken>(db.UserStore, db.RoleStore);
		}

		public static UserStore<MockUser, MockRole, MockUserToken> GetEmptyUserStore() {
			return GetUserStorePrivate();
		}

		public static RoleStore<MockRole, ObjectId, MockUserRole, MockRoleClaim> GetEmptyRoleStore() {
			return GetRoleStorePrivate();
		}

		public static Tuple<RoleStore<MockRole, ObjectId, MockUserRole, MockRoleClaim>, UserStore<MockUser, MockRole, MockUserToken>> GetEmptyStores() {
			return GetStoresPrivate();
		}
	}
}
