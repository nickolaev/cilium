// Code generated by go-swagger; DO NOT EDIT.

// Copyright Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package ipam

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewPostIpamIPParams creates a new PostIpamIPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPostIpamIPParams() *PostIpamIPParams {
	return &PostIpamIPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPostIpamIPParamsWithTimeout creates a new PostIpamIPParams object
// with the ability to set a timeout on a request.
func NewPostIpamIPParamsWithTimeout(timeout time.Duration) *PostIpamIPParams {
	return &PostIpamIPParams{
		timeout: timeout,
	}
}

// NewPostIpamIPParamsWithContext creates a new PostIpamIPParams object
// with the ability to set a context for a request.
func NewPostIpamIPParamsWithContext(ctx context.Context) *PostIpamIPParams {
	return &PostIpamIPParams{
		Context: ctx,
	}
}

// NewPostIpamIPParamsWithHTTPClient creates a new PostIpamIPParams object
// with the ability to set a custom HTTPClient for a request.
func NewPostIpamIPParamsWithHTTPClient(client *http.Client) *PostIpamIPParams {
	return &PostIpamIPParams{
		HTTPClient: client,
	}
}

/*
PostIpamIPParams contains all the parameters to send to the API endpoint

	for the post ipam IP operation.

	Typically these are written to a http.Request.
*/
type PostIpamIPParams struct {

	/* IP.

	   IP address
	*/
	IP string

	// Owner.
	Owner *string
	/*Pool*/
	Pool *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the post ipam IP params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostIpamIPParams) WithDefaults() *PostIpamIPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the post ipam IP params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostIpamIPParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the post ipam IP params
func (o *PostIpamIPParams) WithTimeout(timeout time.Duration) *PostIpamIPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the post ipam IP params
func (o *PostIpamIPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the post ipam IP params
func (o *PostIpamIPParams) WithContext(ctx context.Context) *PostIpamIPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the post ipam IP params
func (o *PostIpamIPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the post ipam IP params
func (o *PostIpamIPParams) WithHTTPClient(client *http.Client) *PostIpamIPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the post ipam IP params
func (o *PostIpamIPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIP adds the ip to the post ipam IP params
func (o *PostIpamIPParams) WithIP(ip string) *PostIpamIPParams {
	o.SetIP(ip)
	return o
}

// SetIP adds the ip to the post ipam IP params
func (o *PostIpamIPParams) SetIP(ip string) {
	o.IP = ip
}

// WithOwner adds the owner to the post ipam IP params
func (o *PostIpamIPParams) WithOwner(owner *string) *PostIpamIPParams {
	o.SetOwner(owner)
	return o
}

// SetOwner adds the owner to the post ipam IP params
func (o *PostIpamIPParams) SetOwner(owner *string) {
	o.Owner = owner
}

// WithPool adds the pool to the post ipam IP params
func (o *PostIpamIPParams) WithPool(pool *string) *PostIpamIPParams {
	o.SetPool(pool)
	return o
}

// SetPool adds the pool to the post ipam IP params
func (o *PostIpamIPParams) SetPool(pool *string) {
	o.Pool = pool
}

// WriteToRequest writes these params to a swagger request
func (o *PostIpamIPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param ip
	if err := r.SetPathParam("ip", o.IP); err != nil {
		return err
	}

	if o.Owner != nil {

		// query param owner
		var qrOwner string

		if o.Owner != nil {
			qrOwner = *o.Owner
		}
		qOwner := qrOwner
		if qOwner != "" {

			if err := r.SetQueryParam("owner", qOwner); err != nil {
				return err
			}
		}
	}

	if o.Pool != nil {

		// query param pool
		var qrPool string
		if o.Pool != nil {
			qrPool = *o.Pool
		}
		qPool := qrPool
		if qPool != "" {
			if err := r.SetQueryParam("pool", qPool); err != nil {
				return err
			}
		}

	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
