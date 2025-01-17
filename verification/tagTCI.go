// Licensed under the Apache-2.0 license

package verification

import (
	"errors"
	//"reflect"
	"testing"
)

// This file is used to test the tagTCI command.

func TestTagTCI(d TestDPEInstance, client DPEClient, t *testing.T) {
	// Try to create the default context if isn't done automatically.
	if !d.GetSupport().AutoInit {
		handle, err := client.InitializeContext(InitIsDefault)
		if err != nil {
			t.Fatalf("Failed to initialize default context: %v", err)
		}
		defer client.DestroyContext(handle, DestroyDescendants)
	}

	tag := TCITag(12345)
	// Check to see our tag is not yet found.
	if _, err := client.GetTaggedTCI(tag); !errors.Is(err, StatusBadTag) {
		t.Fatalf("GetTaggedTCI returned %v, want %v", err, StatusBadTag)
	}

	// Tag the default context
	var ctx ContextHandle

	handle, err := client.TagTCI(&ctx, tag)
	if err != nil {
		t.Fatalf("Could not tag TCI: %v", err)
	}

	if *handle != ctx {
		t.Errorf("New context handle from TagTCI was %x, expected %x", handle, ctx)
	}

	_, err = client.GetTaggedTCI(tag)
	if err != nil {
		t.Fatalf("Could not get tagged TCI: %v", err)
	}

	// TODO: For profiles which use auto-initialization, we don't know the expected
	// TCIs. Uncomment this once the DeriveChild API is implemented so the test
	// can control the TCI inputs.
	/*
		wantCumulativeTCI := make([]byte, profile.GetDigestSize())
		if !reflect.DeepEqual(taggedTCI.CumulativeTCI, wantCumulativeTCI) {
			t.Errorf("GetTaggedTCI returned cumulative TCI %x, expected %x", taggedTCI.CumulativeTCI, wantCumulativeTCI)
		}

		wantCurrentTCI := make([]byte, profile.GetDigestSize())
		if !reflect.DeepEqual(taggedTCI.CurrentTCI, wantCurrentTCI) {
			t.Errorf("GetTaggedTCI returned current TCI %x, expected %x", taggedTCI.CurrentTCI, wantCurrentTCI)
		}
	*/

	// Make sure some other tag is still not found.
	if _, err := client.GetTaggedTCI(TCITag(98765)); !errors.Is(err, StatusBadTag) {
		t.Fatalf("GetTaggedTCI returned %v, want %v", err, StatusBadTag)
	}

	// TODO: When DeriveChild is implemented, call it here to add more TCIs and call TagTCI again.
}
