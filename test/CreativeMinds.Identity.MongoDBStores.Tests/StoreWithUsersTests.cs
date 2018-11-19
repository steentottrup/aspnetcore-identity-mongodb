using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using System;
using System.Linq;
using Xunit;

namespace CreativeMinds.Identity.MongoDBStores.Tests {

	public class StoreWithUsersTests {

		[Fact]
		public void CreateUsers() {
			UserStore<MockUser, MockRole, MockUserToken> userStore = TestInit.GetEmptyUserStore();

			String emailAddress1 = "test1@creativeminds.dk";
			String userName1 = "MisterTest1";
			IdentityResult result = userStore.CreateAsync(new MockUser { Email = emailAddress1, UserName = userName1 }, new System.Threading.CancellationToken()).Result;

			Assert.True(result.Succeeded == true);

			String emailAddress2 = "test2@creativeminds.dk";
			String userName2 = "MisterTest2";
			result = userStore.CreateAsync(new MockUser { Email = emailAddress2, UserName = userName2 }, new System.Threading.CancellationToken()).Result;

			Assert.True(result.Succeeded == true);

			String emailAddress3 = "test3@creativeminds.dk";
			String userName3 = "MisterTest3";
			result = userStore.CreateAsync(new MockUser { Email = emailAddress3, UserName = userName3 }, new System.Threading.CancellationToken()).Result;

			Assert.True(result.Succeeded == true);

			Assert.True(userStore.Users.Count() == 3);
		}
	}
}
