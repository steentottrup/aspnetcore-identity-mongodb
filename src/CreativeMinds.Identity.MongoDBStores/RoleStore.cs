using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace CreativeMinds.Identity.MongoDBStores {

	public class RoleStore<TRole, TKey, TUserRole, TRoleClaim> : IQueryableRoleStore<TRole>, IRoleStore<TRole>, IDisposable, IRoleClaimStore<TRole>
		where TRole : MongoDBIdentityRole
		where TKey : IEquatable<TKey>
		where TUserRole : IdentityUserRole<TKey>, new()
		where TRoleClaim : IdentityRoleClaim<TKey>, new() {

		private readonly IMongoCollection<TRole> roleCollection;

		public RoleStore(IMongoCollection<TRole> roleCollection, IdentityErrorDescriber describer = null) {
			this.roleCollection = roleCollection;
		}

		public virtual IQueryable<TRole> Roles => this.roleCollection.AsQueryable();

		public virtual Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			if (role == null) {
				throw new ArgumentNullException(nameof(role));
			}
			if (claim == null) {
				throw new ArgumentNullException(nameof(claim));
			}
			List<IdentityRoleClaim> newList = new List<IdentityRoleClaim>(role.Claims);
			newList.Add(new IdentityRoleClaim(claim));
			role.Claims = newList;

			return Task.CompletedTask;
		}

		public async virtual Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			if (role == null) {
				throw new ArgumentNullException(nameof(role));
			}

			await this.roleCollection.InsertOneAsync(role, cancellationToken: cancellationToken);
			return IdentityResult.Success;
		}

		public async virtual Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			if (role == null) {
				throw new ArgumentNullException(nameof(role));
			}

			DeleteResult result = await this.roleCollection.DeleteOneAsync(r => r.Id == role.Id, cancellationToken);
			return result.DeletedCount == 1 ? IdentityResult.Success : IdentityResult.Failed();
		}

		public void Dispose() { }

		public virtual Task<TRole> FindByIdAsync(String roleId, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			ObjectId id;
			if (ObjectId.TryParse(roleId, out id)) {
				return this
						.roleCollection.Find(r => r.Id == id)
						.SingleOrDefaultAsync(cancellationToken);
			}

			return null;
		}

		public virtual Task<TRole> FindByNameAsync(String normalizedName, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			return this
					.roleCollection.Find(r => r.NormalizedName == normalizedName)
					.SingleOrDefaultAsync(cancellationToken);
		}

		public async virtual Task<IList<Claim>> GetClaimsAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			if (role == null) {
				throw new ArgumentNullException(nameof(role));
			}

			return await Task.FromResult(role.Claims.Select(cl => new Claim(cl.ClaimType, cl.ClaimValue)).ToList());
		}

		public Task<String> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			return Task.FromResult(role.NormalizedName);
		}

		public Task<String> GetRoleIdAsync(TRole role, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			return Task.FromResult(role.Id.ToString());
		}

		public Task<String> GetRoleNameAsync(TRole role, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();

			return Task.FromResult(role.Name);
		}

		public virtual Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			if (role == null) {
				throw new ArgumentNullException(nameof(role));
			}
			if (claim == null) {
				throw new ArgumentNullException(nameof(claim));
			}

			IEnumerable<IdentityRoleClaim> claims = role.Claims.Where(rc => rc.RoleId == role.Id && rc.ClaimValue == claim.Value && rc.ClaimType == claim.Type);
			List<IdentityRoleClaim> newList = new List<IdentityRoleClaim>(role.Claims);
			foreach (IdentityRoleClaim c in claims) {
				newList.Remove(c);
			}
			role.Claims = newList;

			return Task.CompletedTask;
		}

		public Task SetNormalizedRoleNameAsync(TRole role, String normalizedName, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();
			role.NormalizedName = normalizedName;

			return Task.CompletedTask;
		}

		public Task SetRoleNameAsync(TRole role, String roleName, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();
			role.Name = roleName;

			return Task.CompletedTask;
		}

		public virtual async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken)) {
			cancellationToken.ThrowIfCancellationRequested();

			// TODO: Log document etc!!!
			ReplaceOneResult result = await this.roleCollection.ReplaceOneAsync<TRole>(r => r.Id == role.Id, role, cancellationToken: cancellationToken);
			return result.ModifiedCount == 1 ? IdentityResult.Success : IdentityResult.Failed();
		}
	}
}
