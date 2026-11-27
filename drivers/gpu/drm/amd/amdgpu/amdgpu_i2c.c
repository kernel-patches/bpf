/*
 * Copyright 2007-8 Advanced Micro Devices, Inc.
 * Copyright 2008 Red Hat Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: Dave Airlie
 *          Alex Deucher
 */

#include <linux/pci.h>

#include <drm/drm_edid.h>
#include <drm/amdgpu_drm.h>
#include "amdgpu.h"
#include "amdgpu_i2c.h"
#include "amdgpu_atombios.h"
#include "atom.h"

/* bit banging i2c */
static int amdgpu_i2c_pre_xfer(struct i2c_adapter *i2c_adap)
{
	struct amdgpu_i2c_chan *i2c = i2c_get_adapdata(i2c_adap);
	struct amdgpu_device *adev = drm_to_adev(i2c->dev);
	struct amdgpu_i2c_bus_rec *rec = &i2c->rec;
	uint32_t temp;

	mutex_lock(&i2c->mutex);

	/* switch the pads to ddc mode */
	if (rec->hw_capable) {
		temp = RREG32(rec->mask_clk_reg);
		temp &= ~(1 << 16);
		WREG32(rec->mask_clk_reg, temp);
	}

	/* clear the output pin values */
	temp = RREG32(rec->a_clk_reg) & ~rec->a_clk_mask;
	WREG32(rec->a_clk_reg, temp);

	temp = RREG32(rec->a_data_reg) & ~rec->a_data_mask;
	WREG32(rec->a_data_reg, temp);

	/* set the pins to input */
	temp = RREG32(rec->en_clk_reg) & ~rec->en_clk_mask;
	WREG32(rec->en_clk_reg, temp);

	temp = RREG32(rec->en_data_reg) & ~rec->en_data_mask;
	WREG32(rec->en_data_reg, temp);

	/* mask the gpio pins for software use */
	temp = RREG32(rec->mask_clk_reg) | rec->mask_clk_mask;
	WREG32(rec->mask_clk_reg, temp);
	temp = RREG32(rec->mask_clk_reg);

	temp = RREG32(rec->mask_data_reg) | rec->mask_data_mask;
	WREG32(rec->mask_data_reg, temp);
	temp = RREG32(rec->mask_data_reg);

	return 0;
}

static void amdgpu_i2c_post_xfer(struct i2c_adapter *i2c_adap)
{
	struct amdgpu_i2c_chan *i2c = i2c_get_adapdata(i2c_adap);
	struct amdgpu_device *adev = drm_to_adev(i2c->dev);
	struct amdgpu_i2c_bus_rec *rec = &i2c->rec;
	uint32_t temp;

	/* unmask the gpio pins for software use */
	temp = RREG32(rec->mask_clk_reg) & ~rec->mask_clk_mask;
	WREG32(rec->mask_clk_reg, temp);
	temp = RREG32(rec->mask_clk_reg);

	temp = RREG32(rec->mask_data_reg) & ~rec->mask_data_mask;
	WREG32(rec->mask_data_reg, temp);
	temp = RREG32(rec->mask_data_reg);

	mutex_unlock(&i2c->mutex);
}

static int amdgpu_i2c_get_clock(void *i2c_priv)
{
	struct amdgpu_i2c_chan *i2c = i2c_priv;
	struct amdgpu_device *adev = drm_to_adev(i2c->dev);
	struct amdgpu_i2c_bus_rec *rec = &i2c->rec;
	uint32_t val;

	/* read the value off the pin */
	val = RREG32(rec->y_clk_reg);
	val &= rec->y_clk_mask;

	return (val != 0);
}


static int amdgpu_i2c_get_data(void *i2c_priv)
{
	struct amdgpu_i2c_chan *i2c = i2c_priv;
	struct amdgpu_device *adev = drm_to_adev(i2c->dev);
	struct amdgpu_i2c_bus_rec *rec = &i2c->rec;
	uint32_t val;

	/* read the value off the pin */
	val = RREG32(rec->y_data_reg);
	val &= rec->y_data_mask;

	return (val != 0);
}

static void amdgpu_i2c_set_clock(void *i2c_priv, int clock)
{
	struct amdgpu_i2c_chan *i2c = i2c_priv;
	struct amdgpu_device *adev = drm_to_adev(i2c->dev);
	struct amdgpu_i2c_bus_rec *rec = &i2c->rec;
	uint32_t val;

	/* set pin direction */
	val = RREG32(rec->en_clk_reg) & ~rec->en_clk_mask;
	val |= clock ? 0 : rec->en_clk_mask;
	WREG32(rec->en_clk_reg, val);
}

static void amdgpu_i2c_set_data(void *i2c_priv, int data)
{
	struct amdgpu_i2c_chan *i2c = i2c_priv;
	struct amdgpu_device *adev = drm_to_adev(i2c->dev);
	struct amdgpu_i2c_bus_rec *rec = &i2c->rec;
	uint32_t val;

	/* set pin direction */
	val = RREG32(rec->en_data_reg) & ~rec->en_data_mask;
	val |= data ? 0 : rec->en_data_mask;
	WREG32(rec->en_data_reg, val);
}

struct amdgpu_i2c_chan *amdgpu_i2c_create(struct drm_device *dev,
					  const struct amdgpu_i2c_bus_rec *rec,
					  const char *name)
{
	struct amdgpu_i2c_chan *i2c;
	int ret;

	/* don't add the mm_i2c bus unless hw_i2c is enabled */
	if (rec->mm_i2c)
		return NULL;

	i2c = kzalloc_obj(struct amdgpu_i2c_chan);
	if (i2c == NULL)
		return NULL;

	i2c->rec = *rec;
	i2c->adapter.owner = THIS_MODULE;
	i2c->adapter.dev.parent = dev->dev;
	i2c->dev = dev;
	i2c_set_adapdata(&i2c->adapter, i2c);
	mutex_init(&i2c->mutex);
	/* set the amdgpu bit adapter */
	snprintf(i2c->adapter.name, sizeof(i2c->adapter.name),
		 "AMDGPU i2c bit bus %s", name);
	i2c->adapter.algo_data = &i2c->bit;
	i2c->bit.pre_xfer = amdgpu_i2c_pre_xfer;
	i2c->bit.post_xfer = amdgpu_i2c_post_xfer;
	i2c->bit.setsda = amdgpu_i2c_set_data;
	i2c->bit.setscl = amdgpu_i2c_set_clock;
	i2c->bit.getsda = amdgpu_i2c_get_data;
	i2c->bit.getscl = amdgpu_i2c_get_clock;
	i2c->bit.udelay = 10;
	i2c->bit.timeout = usecs_to_jiffies(2200);	/* from VESA */
	i2c->bit.data = i2c;
	ret = i2c_bit_add_bus(&i2c->adapter);
	if (ret) {
		DRM_ERROR("Failed to register bit i2c %s\n", name);
		goto out_free;
	}

	return i2c;
out_free:
	kfree(i2c);
	return NULL;

}

void amdgpu_i2c_init(struct amdgpu_device *adev)
{
	if (!adev->is_atom_fw) {
		if (!amdgpu_device_has_dc_support(adev)) {
			amdgpu_atombios_i2c_init(adev);
		} else {
			switch (adev->asic_type) {
			case CHIP_POLARIS10:
			case CHIP_POLARIS11:
			case CHIP_POLARIS12:
				amdgpu_atombios_oem_i2c_init(adev, 0x97);
				break;
			default:
				break;
			}
		}
	}
}

/* remove all the buses */
void amdgpu_i2c_fini(struct amdgpu_device *adev)
{
	int i;

	for (i = 0; i < AMDGPU_MAX_I2C_BUS; i++)
		if (adev->i2c_bus[i])
			adev->i2c_bus[i] = NULL;
}

/* looks up bus based on id */
struct amdgpu_i2c_chan *
amdgpu_i2c_lookup(struct amdgpu_device *adev,
		  const struct amdgpu_i2c_bus_rec *i2c_bus)
{
	int i;

	for (i = 0; i < AMDGPU_MAX_I2C_BUS; i++) {
		if (adev->i2c_bus[i] &&
		    (adev->i2c_bus[i]->rec.i2c_id == i2c_bus->i2c_id)) {
			return adev->i2c_bus[i];
		}
	}
	return NULL;
}
