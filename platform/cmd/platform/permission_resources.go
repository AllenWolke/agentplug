package main

import (
	"context"
	"github.com/lexagent/platform/cmd/internal/permissionresources"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type permissionResourceCatalog = permissionresources.Catalog

type publishedPermissionResourceResolver struct {
	catalog  permissionResourceCatalog
	policies policyasset.Resolver
	skills   interface {
		PublishedSkillAvailable(context.Context, sharedkernel.Scope, string) (bool, error)
	}
}

func (r publishedPermissionResourceResolver) ResolvePermissionRunAvailability(ctx context.Context, scope sharedkernel.Scope) (string, error) {
	return permissionresources.NewPublishedResolver(r.catalog, r.policies).ResolvePermissionRunAvailability(ctx, scope)
}

func (r publishedPermissionResourceResolver) ResolveAgentUsePackage(ctx context.Context, scope sharedkernel.Scope) (identity.AgentUsePackage, error) {
	pack, err := permissionresources.NewPublishedResolver(r.catalog, r.policies).ResolveAgentUsePackage(ctx, scope)
	if err != nil {
		return identity.AgentUsePackage{}, err
	}
	for _, resource := range pack.Resources {
		if _, err := r.ResolvePermissionResource(ctx, scope, resource.Type, resource.ID); err != nil {
			return identity.AgentUsePackage{}, err
		}
	}
	return pack, nil
}

func (r publishedPermissionResourceResolver) ResolvePermissionResource(ctx context.Context, scope sharedkernel.Scope, typ, id string) (identity.PermissionResource, error) {
	resource, err := permissionresources.NewPublishedResolver(r.catalog, r.policies).ResolvePermissionResource(ctx, scope, typ, id)
	if err != nil || typ != "skill" {
		return resource, err
	}
	if r.skills == nil {
		return identity.PermissionResource{}, identity.ErrInvalidResource
	}
	available, err := r.skills.PublishedSkillAvailable(ctx, scope, id)
	if err != nil {
		return identity.PermissionResource{}, err
	}
	if !available {
		return identity.PermissionResource{}, identity.ErrInvalidResource
	}
	return resource, nil
}

func (r publishedPermissionResourceResolver) ResolveAgentUseRequirements(ctx context.Context, scope sharedkernel.Scope) (identity.AgentUseRequirements, error) {
	result, err := permissionresources.NewPublishedResolver(r.catalog, r.policies).ResolveAgentUseRequirements(ctx, scope)
	if err != nil {
		return result, err
	}
	for _, item := range result.Requirements {
		if item.ResourceType == "skill" {
			if _, err := r.ResolvePermissionResource(ctx, scope, "skill", item.ResourceID); err != nil {
				return identity.AgentUseRequirements{}, err
			}
		}
	}
	return result, nil
}

func (r publishedPermissionResourceResolver) ValidateWorkloadBindingVersions(ctx context.Context, scope sharedkernel.Scope, versions []string) error {
	return permissionresources.NewPublishedResolver(r.catalog, r.policies).ValidateWorkloadBindingVersions(ctx, scope, versions)
}
