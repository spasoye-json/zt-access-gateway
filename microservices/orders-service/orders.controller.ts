import { Controller, Get, Post, Put, Delete, Param, Body, Query } from '@nestjs/common';

export interface Order {
  id: string;
  userId: string;
  items: OrderItem[];
  status: 'pending' | 'processing' | 'shipped' | 'delivered' | 'cancelled';
  total: number;
  createdAt: Date;
}

export interface OrderItem {
  sku: string;
  name: string;
  quantity: number;
  price: number;
}

@Controller('orders')
export class OrdersController {
  private orders: Order[] = [
    { 
      id: '1', 
      userId: '1', 
      items: [{ sku: 'SKU001', name: 'Widget', quantity: 2, price: 19.99 }], 
      status: 'delivered', 
      total: 39.98, 
      createdAt: new Date('2023-01-01') 
    },
    { 
      id: '2', 
      userId: '2', 
      items: [{ sku: 'SKU002', name: 'Gadget', quantity: 1, price: 29.99 }], 
      status: 'processing', 
      total: 29.99, 
      createdAt: new Date('2023-01-02') 
    },
  ];

  @Get()
  getOrders(
    @Query('userId') userId?: string,
    @Query('status') status?: string,
    @Query('limit') limit?: string,
    @Query('offset') offset?: string,
  ): Order[] {
    let filteredOrders = this.orders;
    
    if (userId) {
      filteredOrders = filteredOrders.filter(o => o.userId === userId);
    }
    
    if (status) {
      filteredOrders = filteredOrders.filter(o => o.status === status);
    }
    
    const limitNum = limit ? parseInt(limit, 10) : filteredOrders.length;
    const offsetNum = offset ? parseInt(offset, 10) : 0;
    
    return filteredOrders.slice(offsetNum, offsetNum + limitNum);
  }

  @Get(':id')
  getOrder(@Param('id') id: string): Order {
    const order = this.orders.find(o => o.id === id);
    if (!order) {
      throw new Error(`Order with id ${id} not found`);
    }
    return order;
  }

  @Post()
  createOrder(@Body() createOrderDto: Omit<Order, 'id' | 'createdAt'>): Order {
    const newOrder: Order = {
      id: (this.orders.length + 1).toString(),
      ...createOrderDto,
      createdAt: new Date(),
    };
    
    this.orders.push(newOrder);
    return newOrder;
  }

  @Put(':id')
  updateOrder(@Param('id') id: string, @Body() updateOrderDto: Partial<Order>): Order {
    const orderIndex = this.orders.findIndex(o => o.id === id);
    if (orderIndex === -1) {
      throw new Error(`Order with id ${id} not found`);
    }
    
    this.orders[orderIndex] = { ...this.orders[orderIndex], ...updateOrderDto };
    return this.orders[orderIndex];
  }

  @Delete(':id')
  deleteOrder(@Param('id') id: string): { message: string } {
    const orderIndex = this.orders.findIndex(o => o.id === id);
    if (orderIndex === -1) {
      throw new Error(`Order with id ${id} not found`);
    }
    
    this.orders.splice(orderIndex, 1);
    return { message: `Order with id ${id} has been deleted` };
  }
}