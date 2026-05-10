# Software Design Patterns — Quick Reference

## Creational
- **Factory Method**: create objects without specifying exact class; use when subclass determines type
- **Builder**: construct complex objects step by step; use for objects with many optional params
- **Singleton**: one instance globally; use sparingly — prefer dependency injection
- **Prototype**: clone existing objects; use when object creation is expensive

## Structural
- **Adapter**: make incompatible interfaces work together; wraps legacy code
- **Decorator**: add behaviour without subclassing; HTTP middleware is a classic example
- **Facade**: simple interface over complex subsystem; reduces coupling
- **Proxy**: control access to object; use for caching, auth checks, logging

## Behavioural
- **Strategy**: swap algorithm at runtime; replaces switch/if chains on type
- **Observer**: notify many objects of state change; event systems, pub-sub
- **Command**: encapsulate request as object; enables undo, queuing, logging
- **Chain of Responsibility**: pass request along handler chain; middleware pipelines

## Distributed Systems Patterns
- **Circuit Breaker**: stop calling a failing service; open after N failures, retry after timeout
- **Saga**: manage distributed transactions with compensating transactions
- **CQRS**: separate read and write models; enables independent scaling
- **Event Sourcing**: store events not state; enables replay and audit trail
- **Outbox Pattern**: reliably publish events alongside DB writes; prevents dual-write problem

## SOLID Principles
- **S** Single Responsibility: one reason to change
- **O** Open/Closed: open for extension, closed for modification
- **L** Liskov Substitution: subtypes must be substitutable for base types
- **I** Interface Segregation: many specific interfaces over one general
- **D** Dependency Inversion: depend on abstractions, not concretions
