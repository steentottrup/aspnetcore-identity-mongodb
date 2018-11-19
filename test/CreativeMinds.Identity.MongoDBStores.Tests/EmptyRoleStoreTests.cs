using Microsoft.AspNetCore.Identity;
using System;
using System.Linq;
using Xunit;

namespace CreativeMinds.Identity.MongoDBStores.Tests {

	public class EmptyRoleStoreTests {

		[Fact]
		public void CreateRole() {
			var roleStore = TestInit.GetEmptyRoleStore();
			IdentityResult result = roleStore.CreateAsync(new MockRole { Name = "FirstOne" }, new System.Threading.CancellationToken()).Result;

			Assert.True(result.Succeeded == true);
		}

		[Fact]
		public void CreateAndFetchRole() {
			var roleStore = TestInit.GetEmptyRoleStore();
			String name = "FirstOne";
			var role = new MockRole { Name = name };
			IdentityResult result = roleStore.CreateAsync(role, new System.Threading.CancellationToken()).Result;

			Assert.True(result.Succeeded == true);

			var roles = roleStore.Roles.ToList();

			Assert.Collection(roles, (ux) => {
				Assert.Equal(name, ux.Name);
			});

			var rls = roles.FirstOrDefault(u => u.Name == name);

			role = roleStore.FindByNameAsync(role.NormalizedName, new System.Threading.CancellationToken()).Result;

			Assert.NotNull(role);
		}
	}
}
